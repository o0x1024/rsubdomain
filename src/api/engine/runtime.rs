use log::warn;
use rand::Rng;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use crate::send;
use crate::send::SendDog;
use crate::state::BruteForceState;
use crate::structs::RetryStruct;

use super::SubdomainBruteEngine;
use crate::api::{BruteForceProgress, BruteForceProgressPhase};

impl SubdomainBruteEngine {
    pub(super) async fn handle_timeout_domains_with_state(
        running: Arc<AtomicBool>,
        senddog: Arc<Mutex<SendDog>>,
        retry_send: mpsc::Sender<Arc<std::sync::RwLock<RetryStruct>>>,
        state: BruteForceState,
        max_retries: u8,
    ) {
        while running.load(Ordering::Relaxed) {
            let max_length = (1000000 / 10) as usize;
            let datas = state.get_timeout_data(max_length);
            let is_delay = datas.len() > 100;

            for local_data in &datas {
                let index = local_data.index;
                let mut value = local_data.v.clone();

                if value.retry >= max_retries as isize {
                    let _ = state.search_from_index_and_delete(index as u32);
                    continue;
                }

                let dns_name = match senddog.lock() {
                    Ok(guard) => guard.chose_dns(),
                    Err(error) => {
                        warn!("无法锁定 senddog: {}", error);
                        continue;
                    }
                };

                value.retry += 1;
                value.time = chrono::Utc::now().timestamp() as u64;
                value.dns = dns_name;
                let value_clone = value.clone();
                let _ = state.search_from_index_and_delete(index as u32);
                state.append_status(value_clone, index as u32);

                let (flag_id, src_port) = send::generate_flag_index_from_map(index as usize);
                let retry_struct = RetryStruct {
                    domain: value.domain,
                    dns: value.dns,
                    query_type: value.query_type,
                    src_port,
                    flag_id,
                };

                if let Err(error) = retry_send.send(Arc::new(std::sync::RwLock::new(retry_struct)))
                {
                    warn!("重试队列已关闭，无法发送重试数据: {}", error);
                }

                if is_delay {
                    let sleep_duration = rand::thread_rng().gen_range(100..=400);
                    tokio::time::sleep(Duration::from_micros(sleep_duration)).await;
                }
            }

            if datas.is_empty() {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    pub(super) async fn handle_retry_domains_static(
        running: Arc<AtomicBool>,
        senddog: Arc<Mutex<SendDog>>,
        retry_recv: mpsc::Receiver<Arc<std::sync::RwLock<RetryStruct>>>,
    ) {
        while running.load(Ordering::Relaxed) {
            match retry_recv.recv_timeout(Duration::from_millis(1000)) {
                Ok(res) => match res.read() {
                    Ok(retry_data) => match senddog.lock() {
                        Ok(senddog) => {
                            if let Err(error) = senddog.send(
                                retry_data.domain.clone(),
                                retry_data.dns.clone(),
                                retry_data.query_type,
                                retry_data.src_port,
                                retry_data.flag_id,
                            ) {
                                warn!("重试发送失败: {}", error);
                            }
                        }
                        Err(_) => {
                            warn!("无法获取 senddog 锁");
                        }
                    },
                    Err(_) => {
                        warn!("无法读取重试数据");
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    pub(super) async fn wait_for_completion(&self, total_queries: usize) {
        let start_time = std::time::Instant::now();
        let max_wait_time = Duration::from_secs(self.config.max_wait_seconds);
        let mut consecutive_empty_checks = 0;
        let required_consecutive_checks = 5;

        loop {
            if start_time.elapsed() > max_wait_time {
                if !self.config.silent {
                    warn!("等待超时，强制退出等待循环");
                }
                break;
            }

            if self.state.is_local_status_empty() {
                consecutive_empty_checks += 1;
                if consecutive_empty_checks >= required_consecutive_checks {
                    break;
                }
            } else {
                consecutive_empty_checks = 0;
            }

            self.emit_progress(BruteForceProgress {
                phase: BruteForceProgressPhase::WaitingForResponses,
                sent_queries: total_queries,
                total_queries,
                discovered_domains: self.state.discovered_domain_count(),
                current_target: self.config.domains.first().cloned(),
            });

            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    pub(super) fn emit_query_progress(
        &self,
        sent_queries: usize,
        total_queries: usize,
        current_target: Option<&str>,
    ) {
        if sent_queries != 1 && sent_queries % 100 != 0 && sent_queries < total_queries {
            return;
        }

        self.emit_progress(BruteForceProgress {
            phase: BruteForceProgressPhase::SendingQueries,
            sent_queries,
            total_queries,
            discovered_domains: self.state.discovered_domain_count(),
            current_target: current_target.map(|target| target.to_string()),
        });
    }

    pub(super) fn emit_progress(&self, progress: BruteForceProgress) {
        if let Some(callback) = self.config.progress_callback.as_ref() {
            callback(progress);
        }
    }

    pub(super) fn cleanup_resources(&self) {
        self.state.clear_discovered_domains();
        self.state.clear_verification_results();
        self.state.clear_query_state();
    }
}
