use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead};
use rand::Rng;

use crate::device;
use crate::send::SendDog;
use crate::structs::RetryStruct;
use crate::subdata;
use crate::{recv, send, handle};
use crate::wildcard::WildcardDetector;
use crate::verify::{DomainVerifier, VerifyResult};
use crate::dns_resolver::{DnsResolver, DnsResolveResult};
use crate::speed_test::{SpeedTester, BandwidthLimiter};
use crate::input::parse_bandwidth;
use crate::state::BruteForceState;

/// 域名暴破配置
#[derive(Debug, Clone)]
pub struct SubdomainBruteConfig {
    /// 目标域名列表
    pub domains: Vec<String>,
    /// DNS服务器列表
    pub resolvers: Vec<String>,
    /// 字典文件路径
    pub dictionary_file: Option<String>,
    /// 字典数组（直接传入字典数据）
    pub dictionary: Option<Vec<String>>,
    /// 是否跳过泛解析
    pub skip_wildcard: bool,
    /// 带宽限制 (如 "3M", "5K", "10G")
    pub bandwidth_limit: Option<String>,
    /// 是否启用验证模式
    pub verify_mode: bool,
    /// 是否解析DNS记录
    pub resolve_records: bool,
    /// 是否静默模式
    pub silent: bool,
    /// 网络设备名称
    pub device: Option<String>,
}

impl Default for SubdomainBruteConfig {
    fn default() -> Self {
        SubdomainBruteConfig {
            domains: Vec::new(),
            resolvers: Vec::new(),
            dictionary_file: None,
            dictionary: None,
            skip_wildcard: true,
            bandwidth_limit: Some("3M".to_string()),
            verify_mode: false,
            resolve_records: false,
            silent: false,
            device: None,
        }
    }
}

/// 域名暴破结果
#[derive(Debug, Clone)]
pub struct SubdomainResult {
    pub domain: String,
    pub ip: String,
    pub record_type: String,
    pub verified: Option<VerifyResult>,
    pub dns_records: Option<DnsResolveResult>,
}

/// 域名暴破引擎
pub struct SubdomainBruteEngine {
    config: SubdomainBruteConfig,
    wildcard_detector: Option<WildcardDetector>,
    verifier: Option<DomainVerifier>,
    dns_resolver: Option<DnsResolver>,
    bandwidth_limiter: Option<BandwidthLimiter>,
    state: BruteForceState,
}

impl SubdomainBruteEngine {
    /// 创建新的暴破引擎
    pub async fn new(config: SubdomainBruteConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let wildcard_detector = if config.skip_wildcard {
            Some(WildcardDetector::new().await?)
        } else {
            None
        };

        let verifier = if config.verify_mode {
            Some(DomainVerifier::new(10)?)
        } else {
            None
        };

        let dns_resolver = if config.resolve_records {
            Some(DnsResolver::new().await?)
        } else {
            None
        };

        let bandwidth_limiter = if let Some(ref bandwidth) = config.bandwidth_limit {
            let bytes_per_sec = parse_bandwidth(bandwidth)?;
            Some(BandwidthLimiter::new(bytes_per_sec))
        } else {
            None
        };

        Ok(SubdomainBruteEngine {
            config,
            wildcard_detector,
            verifier,
            dns_resolver,
            bandwidth_limiter,
            state: BruteForceState::new(),
        })
    }

    /// 运行子域名暴破
    pub async fn run_brute_force(&self) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        let mut discovered_domains = Vec::new();

        // 检测泛解析
        if let Some(ref detector) = self.wildcard_detector {
            for domain in &self.config.domains {
                if detector.detect_wildcard(domain).await? {
                    if !self.config.silent {
                        println!("检测到泛解析域名: {}", domain);
                    }
                }
            }
        }

        // 执行核心暴破逻辑
        let core_results = self.run_core_brute_force().await?;
        
        // 过滤泛解析结果
        for result in core_results {
            let should_skip = if let Some(ref detector) = self.wildcard_detector {
                if let Ok(ip) = result.ip.parse() {
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

        // HTTP/HTTPS验证
        if let Some(ref verifier) = self.verifier {
            let verify_results = verifier.verify_domains(discovered_domains.clone()).await;
            let verify_map: std::collections::HashMap<String, VerifyResult> = 
                verify_results.into_iter().map(|r| (r.domain.clone(), r)).collect();

            for result in &mut results {
                if let Some(verify_result) = verify_map.get(&result.domain) {
                    result.verified = Some(verify_result.clone());
                }
            }
        }

        // DNS记录解析
        if let Some(ref resolver) = self.dns_resolver {
            let dns_results = resolver.resolve_domains(discovered_domains).await;
            let dns_map: std::collections::HashMap<String, DnsResolveResult> = 
                dns_results.into_iter().map(|r| (r.domain.clone(), r)).collect();

            for result in &mut results {
                if let Some(dns_result) = dns_map.get(&result.domain) {
                    result.dns_records = Some(dns_result.clone());
                }
            }
        }

        Ok(results)
    }

    /// 核心暴破逻辑（整合原有的DNS查询逻辑）
    async fn run_core_brute_force(&self) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
        // 清空之前的结果
        self.state.clear_discovered_domains();
        
        // 选择网络设备
        let ether = if let Some(device_name) = &self.config.device {
            match device::get_device_by_name(device_name) {
                Some(device) => {
                    if !self.config.silent {
                        println!("使用指定网络设备: {}", device_name);
                    }
                    device
                }
                None => {
                    if !self.config.silent {
                        eprintln!("未找到指定的网络设备: {}，使用自动检测", device_name);
                    }
                    device::auto_get_devices().await
                }
            }
        } else {
            device::auto_get_devices().await
        };

        if !self.config.silent {
            println!("使用网络设备: {:?}", ether.device);
        }

        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let flag_id: u16 = rng.gen_range(400..655);
        let device_clone = ether.device.clone();
        let running = Arc::new(AtomicBool::new(true));

        let senddog = Arc::new(Mutex::new(SendDog::new(ether, self.config.resolvers.clone(), flag_id)));

        // 获取字典数据
        let sub_domain_list = if let Some(ref dictionary) = self.config.dictionary {
            // 优先使用传入的字典数组
            dictionary.clone()
        } else if let Some(ref file_path) = self.config.dictionary_file {
            // 其次使用字典文件
            Self::load_dictionary_from_file(file_path)?
        } else {
            // 最后使用默认字典
            subdata::get_default_sub_next_data().iter().map(|&s| s.to_string()).collect()
        };

        let (dns_send, dns_recv) = mpsc::channel();
        let (retry_send, retry_recv): (
            mpsc::Sender<Arc<std::sync::RwLock<RetryStruct>>>,
            mpsc::Receiver<Arc<std::sync::RwLock<RetryStruct>>>,
        ) = mpsc::channel();

        // 启动收包任务
        let running_clone = running.clone();
        let silent = self.config.silent;
        let handle1 = tokio::spawn(async move {
            recv::recv(device_clone, dns_send, running_clone);
        });

        // 启动DNS包处理任务
        let running_clone = running.clone();
        let state_clone = self.state.clone();
        let handle2 = tokio::spawn(async move {
            handle::handle_dns_packet(dns_recv, flag_id, running_clone, silent, state_clone);
        });

        // 启动超时和重试处理任务
        let running_clone = running.clone();
        let senddog_clone = senddog.clone();
        let state_clone = self.state.clone();
        let handle3 = tokio::spawn(async move {
            Self::handle_timeout_domains_with_state(running_clone, senddog_clone, retry_send, state_clone).await;
        });

        let running_clone = running.clone();
        let senddog_clone = senddog.clone();
        let handle4 = tokio::spawn(async move {
            Self::handle_retry_domains_static(running_clone, senddog_clone, retry_recv).await;
        });

        // 创建带宽限制器（如果需要）
        let bandwidth_limiter = if let Some(ref limit_str) = self.config.bandwidth_limit {
            if let Ok(limit) = crate::input::parse_bandwidth(limit_str) {
                Some(crate::speed_test::BandwidthLimiter::new(limit))
            } else {
                None
            }
        } else {
            None
        };

        // 发送DNS查询
        let query_count = self.send_dns_queries(&senddog, &sub_domain_list, &bandwidth_limiter).await?;
        
        if !self.config.silent {
            println!("子域名查询数量: {}", query_count);
        }

        // 等待所有查询完成
        self.wait_for_completion().await;
        running.store(false, Ordering::Relaxed);
        
        // 等待所有后台任务完成
        let _ = tokio::join!(handle1, handle2, handle3, handle4);

        // 显式清理底层网络资源
        // 通过drop senddog来释放DataLinkSender句柄
        drop(senddog);

        // 获取发现的域名并转换为结果格式（在清理之前）
        let discovered = self.state.get_discovered_domains();
        let results: Vec<SubdomainResult> = discovered.into_iter().map(|d| SubdomainResult {
            domain: d.domain,
            ip: d.ip,
            record_type: d.record_type,
            verified: None,
            dns_records: None,
        }).collect();

        // 清理所有资源（在获取结果之后）
        self.cleanup_resources();
        
        // 不再强制关闭tokio运行时，让运行时自然结束

        Ok(results)
    }

    /// 从文件加载字典
    fn load_dictionary_from_file(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let file = File::open(file_path)?;
        let reader = io::BufReader::new(file);
        let mut dictionary = Vec::new();
        
        for line in reader.lines() {
            if let Ok(word) = line {
                dictionary.push(word.trim().to_string());
            }
        }
        
        Ok(dictionary)
    }

    /// 发送DNS查询
    async fn send_dns_queries(
        &self,
        senddog: &Arc<Mutex<SendDog>>,
        sub_domain_list: &[String],
        bandwidth_limiter: &Option<crate::speed_test::BandwidthLimiter>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut count = 0;
        
        // 如果有字典文件，优先使用文件中的数据
        if let Some(ref file_path) = self.config.dictionary_file {
            count = self.send_queries_from_file(file_path, senddog, bandwidth_limiter).await?;
        } else {
            count = self.send_queries_from_list(sub_domain_list, senddog, bandwidth_limiter).await?;
        }
        
        Ok(count)
    }

    /// 从文件发送查询
    async fn send_queries_from_file(
        &self,
        path: &str,
        senddog: &Arc<Mutex<SendDog>>,
        bandwidth_limiter: &Option<crate::speed_test::BandwidthLimiter>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut count = 0;
        
        for line in reader.lines() {
            if let Ok(sub) = line {
                for domain in &self.config.domains {
                    if let Some(ref limiter) = bandwidth_limiter {
                        limiter.can_send(64).await;
                    }
                    
                    let mut senddog = senddog.lock().unwrap();
                    let mut final_domain = sub.clone();
                    final_domain.push_str(".");
                    final_domain = final_domain + domain;
                    
                    let dns_name = senddog.chose_dns();
                    let (flagid2, scr_port) =
                        senddog.build_status_table(final_domain.as_str(), dns_name.as_str(), 1);
                    senddog.send(final_domain, dns_name, scr_port, flagid2);
                    count += 1;
                }
            }
        }
        
        Ok(count)
    }

    /// 从列表发送查询
    async fn send_queries_from_list(
        &self,
        sub_domain_list: &[String],
        senddog: &Arc<Mutex<SendDog>>,
        bandwidth_limiter: &Option<crate::speed_test::BandwidthLimiter>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut count = 0;
        
        for sub in sub_domain_list {
            for domain in &self.config.domains {
                if let Some(ref limiter) = bandwidth_limiter {
                    limiter.can_send(64).await;
                }
                
                let mut senddog = senddog.lock().unwrap();
                let mut final_domain = sub.clone();
                final_domain.push_str(".");
                final_domain = final_domain + domain;
                
                let dns_name = senddog.chose_dns();
                let (flagid2, scr_port) =
                    senddog.build_status_table(final_domain.as_str(), dns_name.as_str(), 1);
                senddog.send(final_domain, dns_name, scr_port, flagid2);
                count += 1;
            }
        }
        
        Ok(count)
    }

    /// 处理超时域名（带状态参数）
    async fn handle_timeout_domains_with_state(
        running: Arc<AtomicBool>,
        senddog: Arc<Mutex<SendDog>>,
        retry_send: mpsc::Sender<Arc<std::sync::RwLock<RetryStruct>>>,
        state: BruteForceState,
    ) {
        while running.load(Ordering::Relaxed) {
            let mut is_delay = true;
            let max_length = (1000000 / 10) as usize;
            let datas = state.get_timeout_data(max_length);
            is_delay = datas.len() > 100;

            for local_data in &datas {
                let index = local_data.index;
                let mut value = local_data.v.clone();

                if value.retry >= 5 {
                    match state.search_from_index_and_delete(index as u32) {
                        Ok(_data) => {
                            // 删除失败项
                        }
                        Err(_) => (),
                    }
                    continue;
                }
                
                let dns_name = {
                    let senddog = senddog.lock().unwrap();
                    senddog.chose_dns()
                };
                value.retry += 1;
                value.time = chrono::Utc::now().timestamp() as u64;
                value.dns = dns_name;
                let value_c = value.clone();
                let _ = state.search_from_index_and_delete(index as u32);
                state.append_status(value_c, index as u32);

                let (flag_id, src_port) = send::generate_flag_index_from_map(index as usize);
                let retry_struct = RetryStruct {
                    domain: value.domain,
                    dns: value.dns,
                    src_port,
                    flag_id,
                    domain_level: value.domain_level as usize,
                };
                
                let _ = retry_send.send(Arc::new(std::sync::RwLock::new(retry_struct))).unwrap();

                if is_delay {
                    let sleep_duration = rand::thread_rng().gen_range(100..=400);
                    tokio::time::sleep(Duration::from_micros(sleep_duration)).await;
                }
            }

            // 如果没有超时数据，短暂休眠后继续
            if datas.is_empty() {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    /// 处理重试域名（静态方法）
    async fn handle_retry_domains_static(
        running: Arc<AtomicBool>,
        senddog: Arc<Mutex<SendDog>>,
        retry_recv: mpsc::Receiver<Arc<std::sync::RwLock<RetryStruct>>>,
    ) {
        while running.load(Ordering::Relaxed) {
            match retry_recv.recv_timeout(Duration::from_millis(1000)) {
                Ok(res) => {
                    match res.read() {
                        Ok(rety_data) => {
                            match senddog.lock() {
                                Ok(senddog) => {
                                    senddog.send(
                                        rety_data.domain.clone(),
                                        rety_data.dns.clone(),
                                        rety_data.src_port,
                                        rety_data.flag_id,
                                    )
                                }
                                Err(_) => {
                                    println!("警告: 无法获取senddog锁");
                                }
                            }
                        }
                        Err(_) => {
                            println!("警告: 无法读取重试数据");
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // 超时是正常的，继续循环
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // 通道已断开，退出循环
                    break;
                }
            }
        }
    }

    /// 等待所有查询完成（带超时机制）
    async fn wait_for_completion(&self) {
        let start_time = std::time::Instant::now();
        let max_wait_time = Duration::from_secs(300); // 最大等待5分钟
        let mut consecutive_empty_checks = 0;
        let required_consecutive_checks = 5; // 需要连续5次检查都为空才确认完成
        
        loop {
            // 检查是否超时
            if start_time.elapsed() > max_wait_time {
                if !self.config.silent {
                    println!("警告: 等待超时，强制退出等待循环");
                }
                break;
            }
            
            if self.state.is_local_status_empty() {
                consecutive_empty_checks += 1;
                if consecutive_empty_checks >= required_consecutive_checks {
                    if !self.config.silent {
                        println!("所有查询已完成");
                    }
                    break;
                }
            } else {
                consecutive_empty_checks = 0;
            }
            
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    /// 显式清理所有资源
    fn cleanup_resources(&self) {
        // 清理状态数据
        self.state.clear_discovered_domains();
        self.state.clear_verification_results();
        
        // 强制清理全局状态
        #[cfg(feature = "global_cleanup")]
        {
            use crate::handle::{clear_discovered_domains, clear_verification_results};
            clear_discovered_domains();
            clear_verification_results();
        }
        
        // 清理全局静态变量（关键修复）
        // 这些全局变量使用lazy_static定义，可能导致进程无法退出
        Self::cleanup_global_state();
    }

    /// 清理全局状态，释放Arc引用
    fn cleanup_global_state() {
        // 清空全局静态变量
        if let Ok(mut status) = crate::structs::LOCAL_STATUS.write() {
            *status = crate::local_struct::LocalStruct::new();
        }
        
        if let Ok(mut stack) = crate::structs::LOCAL_STACK.write() {
            *stack = crate::stack::Stack::new();
        }
        
        // 清理handle模块中的全局状态
        crate::handle::cleanup_global_state();
    }
    


}

/// 便捷的域名暴破函数（使用字典文件）
pub async fn brute_force_subdomains(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file,
        dictionary: None,
        resolvers: resolvers.unwrap_or_else(|| vec!["8.8.8.8".to_string()]),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        resolve_records,
        silent,
        device,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 便捷的域名暴破函数（使用字典数组）
pub async fn brute_force_subdomains_with_dict(
    domains: Vec<String>,
    dictionary: Vec<String>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file: None,
        dictionary: Some(dictionary),
        resolvers: resolvers.unwrap_or_else(|| vec!["8.8.8.8".to_string()]),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        resolve_records,
        silent,
        device,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 便捷的域名暴破函数（完整配置）
pub async fn brute_force_subdomains_with_config(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    dictionary: Option<Vec<String>>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file,
        dictionary,
        resolvers: resolvers.unwrap_or_else(|| vec!["8.8.8.8".to_string()]),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        resolve_records,
        silent,
        device,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 网速测试函数
pub async fn run_speed_test(duration_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    let tester = SpeedTester::new().await;
    let result = tester.run_speed_test(duration_secs).await;
    tester.display_result(&result);
    Ok(())
}