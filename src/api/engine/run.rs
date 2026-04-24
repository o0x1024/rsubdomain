use log::{info, warn};
use rand::Rng;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use crate::api::dictionary::resolve_dictionary;
use crate::api::{BruteForceProgress, BruteForceProgressPhase, SubdomainResult};
use crate::handle;
use crate::model::PacketTransport;
use crate::recv;
use crate::resolver_defaults::default_resolvers;
use crate::send::SendDog;
use crate::structs::RetryStruct;

use super::SubdomainBruteEngine;

impl SubdomainBruteEngine {
    /// 运行子域名暴破
    pub async fn run_brute_force(
        &self,
    ) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        let mut discovered_domains = Vec::new();

        if let Some(ref detector) = self.wildcard_detector {
            for domain in &self.config.domains {
                if detector.detect_wildcard(domain).await? && !self.config.silent {
                    warn!("检测到泛解析域名: {}", domain);
                }
            }
        }

        let core_results = self.run_core_brute_force().await?;

        for result in core_results {
            let should_skip = if let Some(ref detector) = self.wildcard_detector {
                if let Ok(ip) = result.value.parse() {
                    detector.is_wildcard_result(&result.domain, &ip)
                } else {
                    false
                }
            } else {
                false
            };

            if !should_skip {
                discovered_domains.push(result.domain.clone());
                results.push(result);
            }
        }

        #[cfg(feature = "verify")]
        self.attach_verification_results(&mut results, discovered_domains.clone())
            .await;

        #[cfg(feature = "dns-resolver")]
        self.attach_dns_records(&mut results, discovered_domains)
            .await;

        Ok(results)
    }

    async fn run_core_brute_force(
        &self,
    ) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
        self.state.clear_discovered_domains();

        let ether = self.select_network_device().await?;

        if !self.config.silent {
            info!("使用网络设备: {:?}", ether.device);
            if ether.transport == PacketTransport::Udp {
                info!("接口 {} 当前使用 UDP 兼容模式", ether.device);
            }
        }

        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let flag_id: u16 = rng.gen_range(400..655);
        let device_clone = ether.device.clone();
        let local_ip = ether.src_ip;
        let transport = ether.transport;
        let running = Arc::new(AtomicBool::new(true));
        let dns_servers = if self.config.resolvers.is_empty() {
            default_resolvers()
        } else {
            self.config.resolvers.clone()
        };
        let sender = SendDog::new(ether, self.config.resolvers.clone(), flag_id)?;
        let udp_receiver = sender.udp_receiver_socket()?;
        let udp_local_port = sender.local_port()?;
        let senddog = Arc::new(Mutex::new(sender));

        if !self.config.silent {
            if let Some(local_port) = udp_local_port {
                info!("UDP 兼容模式本地端口: {}", local_port);
            }
        }

        let sub_domain_list = resolve_dictionary(
            self.config.dictionary.as_ref(),
            self.config.dictionary_file.as_deref(),
        )?;
        let bandwidth_limiter = self.build_bandwidth_limiter();
        let total_queries = sub_domain_list
            .len()
            .saturating_mul(self.config.domains.len())
            .saturating_mul(self.config.query_types.len().max(1));

        let (dns_send, dns_recv) = mpsc::channel();
        let (retry_send, retry_recv): (
            mpsc::Sender<Arc<std::sync::RwLock<RetryStruct>>>,
            mpsc::Receiver<Arc<std::sync::RwLock<RetryStruct>>>,
        ) = mpsc::channel();

        let handle1 = {
            let running_clone = running.clone();
            match transport {
                PacketTransport::Ethernet => tokio::task::spawn_blocking(move || {
                    recv::recv(
                        device_clone,
                        local_ip,
                        dns_servers,
                        flag_id,
                        dns_send,
                        running_clone,
                    );
                }),
                PacketTransport::Udp => {
                    let socket = udp_receiver.ok_or("UDP兼容模式接收socket未初始化")?;
                    tokio::task::spawn_blocking(move || {
                        recv::recv_udp(socket, dns_send, running_clone);
                    })
                }
            }
        };

        let handle2 = {
            let running_clone = running.clone();
            let state_clone = self.state.clone();
            let show_discovered_records = !self.config.silent && self.config.raw_records;
            match transport {
                PacketTransport::Ethernet => tokio::task::spawn_blocking(move || {
                    handle::handle_dns_packet(
                        dns_recv,
                        flag_id,
                        running_clone,
                        show_discovered_records,
                        state_clone,
                    );
                }),
                PacketTransport::Udp => tokio::task::spawn_blocking(move || {
                    handle::handle_dns_payload(
                        dns_recv,
                        running_clone,
                        show_discovered_records,
                        state_clone,
                    );
                }),
            }
        };

        let query_count = self
            .send_dns_queries(
                &senddog,
                &sub_domain_list,
                &bandwidth_limiter,
                total_queries,
            )
            .await?;

        if !self.config.silent {
            info!("子域名查询数量: {}", query_count);
        }

        let handle3 = {
            let running_clone = running.clone();
            let senddog_clone = senddog.clone();
            let state_clone = self.state.clone();
            let max_retries = self.config.max_retries;
            let dns_timeout_seconds = self.config.dns_timeout_seconds;
            tokio::spawn(async move {
                Self::handle_timeout_domains_with_state(
                    running_clone,
                    senddog_clone,
                    retry_send,
                    state_clone,
                    max_retries,
                    dns_timeout_seconds,
                )
                .await;
            })
        };

        let handle4 = {
            let running_clone = running.clone();
            let senddog_clone = senddog.clone();
            let state_clone = self.state.clone();
            let bandwidth_limiter = bandwidth_limiter.clone();
            tokio::spawn(async move {
                Self::handle_retry_domains_static(
                    running_clone,
                    senddog_clone,
                    state_clone,
                    retry_recv,
                    bandwidth_limiter,
                )
                .await;
            })
        };

        self.wait_for_completion(query_count).await;
        running.store(false, Ordering::Relaxed);

        match transport {
            PacketTransport::Ethernet => {
                if tokio::time::timeout(Duration::from_secs(2), handle1)
                    .await
                    .is_err()
                    && !self.config.silent
                {
                    warn!("以太网接收线程在退出宽限期内未结束，跳过等待以避免进程卡住");
                }
            }
            PacketTransport::Udp => {
                let _ = handle1.await;
            }
        }
        let _ = tokio::join!(handle2, handle3, handle4);
        drop(senddog);

        let results = self.collect_discovered_results();

        self.emit_progress(BruteForceProgress {
            phase: BruteForceProgressPhase::Completed,
            sent_queries: query_count,
            total_queries: query_count.max(total_queries),
            discovered_domains: results.len(),
            current_target: None,
        });

        self.cleanup_resources();

        Ok(results)
    }
}
