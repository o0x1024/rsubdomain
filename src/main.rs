use std::fs::File;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;

use clap::Parser;
use rand;
use rand::Rng;
use rsubdomain::input::{Opts, parse_bandwidth, OutputFormat};
use rsubdomain::send::SendDog;
use rsubdomain::structs::{RetryStruct, LOCAL_STATUS};
use rsubdomain::subdata;
use rsubdomain::{device, handle};
use rsubdomain::{recv, send};
use rsubdomain::wildcard::WildcardDetector;
use rsubdomain::speed_test::SpeedTester;
use rsubdomain::verify::DomainVerifier;
use rsubdomain::dns_resolver::DnsResolver;
use rsubdomain::output::export_results;
use rsubdomain::handle::VerificationResult;
use rsubdomain::state::BruteForceState;
use rsubdomain::structs::LOCAL_STACK;
use rsubdomain::local_struct::LocalStruct;
use rsubdomain::stack::Stack;

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    
    // 网络接口列表
    if opts.list_network {
        list_network_interfaces();
        return;
    }

    // 网速测试
    if opts.network_test {
        if let Err(e) = run_network_speed_test(&opts.target_ip).await {
            eprintln!("网速测试失败: {}", e);
        }
        return;
    }

    // 执行域名暴破
    if let Err(e) = run_subdomain_brute(opts).await {
        eprintln!("域名暴破失败: {}", e);
    }
    println!("程序执行完成");
}

/// 列出网络接口
fn list_network_interfaces() {
    println!("可用网络接口:");
    device::print_network_devices();
}

/// 运行网速测试
async fn run_network_speed_test(target_ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tester = SpeedTester::new_with_target(target_ip).await;
    let result = tester.run_speed_test(10).await; // 测试10秒
    tester.display_result(&result);
    Ok(())
}

/// 执行域名暴破主逻辑
async fn run_subdomain_brute(opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    println!("目标域名: {:?}", opts.domain);
    
    // 选择网络设备
    let ether = if let Some(device_name) = &opts.device {
        match device::get_device_by_name(device_name) {
            Some(device) => {
                println!("使用指定网络设备: {}", device_name);
                device
            }
            None => {
                eprintln!("未找到指定的网络设备: {}，使用自动检测", device_name);
                device::auto_get_devices().await
            }
        }
    } else {
        device::auto_get_devices().await
    };
    
    println!("使用网络设备: {:?}", ether.device);
    
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let flag_id: u16 = rng.gen_range(400..655);
    let device_clone = ether.device.clone();
    let running = Arc::new(AtomicBool::new(true));

    // 带宽限制器
    let bandwidth_limiter = if let Ok(bytes_per_sec) = parse_bandwidth(&opts.bandwidth) {
        Some(rsubdomain::speed_test::BandwidthLimiter::new(bytes_per_sec))
    } else {
        println!("带宽格式错误，使用默认设置");
        None
    };

    // 泛解析检测
    let _wildcard_detector = if opts.skip_wildcard {
        match WildcardDetector::new().await {
            Ok(detector) => {
                // 检测每个域名的泛解析
                for domain in &opts.domain {
                    match detector.detect_wildcard(domain).await {
                        Ok(is_wildcard) => {
                            if is_wildcard {
                                println!("检测到泛解析域名: {}", domain);
                            }
                        }
                        Err(e) => println!("泛解析检测失败 {}: {}", domain, e),
                    }
                }
                Some(detector)
            }
            Err(e) => {
                println!("泛解析检测器初始化失败: {}", e);
                None
            }
        }
    } else {
        None
    };

    let senddog = Arc::new(Mutex::new(SendDog::new(ether, opts.resolvers.clone(), flag_id)));
    let sub_domain_list = subdata::get_default_sub_next_data();
    let state = BruteForceState::new();

    let (dns_send, dns_recv) = mpsc::channel();
    let (retry_send, retry_recv): (
        mpsc::Sender<Arc<RwLock<RetryStruct>>>,
        mpsc::Receiver<Arc<RwLock<RetryStruct>>>,
    ) = mpsc::channel();

    // 启动网卡收包任务
    let packet_receiver_handle = start_packet_receiver(device_clone, dns_send, running.clone()).await;

    // 启动DNS包处理任务
    let dns_handler_handle = start_dns_packet_handler(dns_recv, flag_id, running.clone(), opts.slient, state.clone()).await;

    // 发送DNS查询
    let count = send_dns_queries(&opts, &senddog, &sub_domain_list, &bandwidth_limiter).await?;
    
    println!("子域名查询数量: {}", count);

    // 启动超时和重试处理任务
    let timeout_handler_handle = start_timeout_handler(running.clone(), senddog.clone(), retry_send).await;
    let retry_handler_handle = start_retry_handler(running.clone(), senddog.clone(), retry_recv).await;

    // 等待所有查询完成
    wait_for_completion().await;
    
    // 设置停止标志
    running.store(false, Ordering::Relaxed);
    
    // 等待异步任务优雅退出
    println!("等待后台任务退出...");
    
    // 等待所有异步任务完成，设置超时以避免无限等待
    println!("等待异步任务完成...");
    
    // 逐个等待任务完成，设置超时
    let timeout_duration = Duration::from_secs(5);
    
    let _ = tokio::time::timeout(timeout_duration, packet_receiver_handle).await;
    let _ = tokio::time::timeout(timeout_duration, dns_handler_handle).await;
    let _ = tokio::time::timeout(timeout_duration, timeout_handler_handle).await;
    let _ = tokio::time::timeout(timeout_duration, retry_handler_handle).await;
    
    println!("异步任务等待完成");

    // 获取发现的域名
    let discovered = handle::get_discovered_domains();
    let discovered_domains: Vec<String> = discovered.iter().map(|d| d.domain.clone()).collect();

    // 后处理：验证和DNS解析
    let mut verification_results = Vec::new();
    if opts.verify || opts.resolve_records {
        verification_results = run_post_processing(&discovered_domains, opts.verify, opts.resolve_records).await?;
    }

    // 显示汇总统计
    if opts.summary {
        handle::print_summary();
    }

    // 导出结果
    if let Some(output_path) = opts.output {
        let format = opts.format.parse::<OutputFormat>()
            .unwrap_or_else(|e| {
                eprintln!("输出格式解析错误: {}, 使用默认JSON格式", e);
                OutputFormat::Json
            });
        
        let summary = handle::generate_summary();
        export_results(discovered, verification_results, summary, &output_path, &format)?;
    }

    // 清理全局状态
    cleanup_global_state();
    
    // 给tokio运行时更多时间来清理资源
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("完成");
    Ok(())
}

/// 清理全局状态，释放Arc引用
fn cleanup_global_state() {
    // 清空全局静态变量
    if let Ok(mut status) = LOCAL_STATUS.write() {
        *status = LocalStruct::new();
    }
    
    if let Ok(mut stack) = LOCAL_STACK.write() {
        *stack = Stack::new();
    }
    
    // 清理handle模块中的全局状态
    rsubdomain::handle::cleanup_global_state();
}

/// 启动网卡收包任务
async fn start_packet_receiver(
    device: String, 
    dns_send: mpsc::Sender<Arc<Vec<u8>>>, 
    running: Arc<AtomicBool>
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        recv::recv(device, dns_send, running);
    })
}

/// 启动DNS包处理任务
async fn start_dns_packet_handler(
    dns_recv: mpsc::Receiver<Arc<Vec<u8>>>,
    flag_id: u16,
    running: Arc<AtomicBool>,
    silent: bool,
    state: BruteForceState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        handle::handle_dns_packet(dns_recv, flag_id, running, silent, state);
    })
}

/// 发送DNS查询
async fn send_dns_queries(
    opts: &Opts,
    senddog: &Arc<Mutex<SendDog>>,
    sub_domain_list: &[&str],
    bandwidth_limiter: &Option<rsubdomain::speed_test::BandwidthLimiter>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0;
    
    match &opts.file {
        Some(path) => {
            count = send_queries_from_file(path, opts, senddog, bandwidth_limiter).await?;
        }
        None => {
            count = send_queries_from_builtin_list(sub_domain_list, opts, senddog, bandwidth_limiter).await?;
        }
    }
    
    Ok(count)
}

/// 从文件发送查询
async fn send_queries_from_file(
    path: &str,
    opts: &Opts,
    senddog: &Arc<Mutex<SendDog>>,
    bandwidth_limiter: &Option<rsubdomain::speed_test::BandwidthLimiter>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut count = 0;
    
    for line in reader.lines() {
        if let Ok(sub) = line {
            for domain in &opts.domain {
                if let Some(ref limiter) = bandwidth_limiter {
                    limiter.can_send(64).await;
                }
                
                let mut senddog = senddog.try_lock().unwrap();
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

/// 从内置列表发送查询
async fn send_queries_from_builtin_list(
    sub_domain_list: &[&str],
    opts: &Opts,
    senddog: &Arc<Mutex<SendDog>>,
    bandwidth_limiter: &Option<rsubdomain::speed_test::BandwidthLimiter>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0;
    
    for sub in sub_domain_list {
        for domain in &opts.domain {
            if let Some(ref limiter) = bandwidth_limiter {
                limiter.can_send(64).await;
            }
            
            let mut senddog = senddog.try_lock().unwrap();
            let mut final_domain = sub.to_string();
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

/// 启动超时处理任务
async fn start_timeout_handler(
    running: Arc<AtomicBool>,
    senddog: Arc<Mutex<SendDog>>,
    retry_send: mpsc::Sender<Arc<RwLock<RetryStruct>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        handle_timeout_domains(running, senddog, retry_send).await;
    })
}

/// 处理超时域名（重用原有逻辑）
async fn handle_timeout_domains(
    running: Arc<AtomicBool>,
    senddog: Arc<Mutex<SendDog>>,
    retry_send: mpsc::Sender<Arc<RwLock<RetryStruct>>>,
) {
    while running.load(Ordering::Relaxed) {
        let mut is_delay = true;
        let mut datas = Vec::new();
        
        // 在独立的作用域中获取数据，确保锁在await之前释放
        let lock_failed = {
            match LOCAL_STATUS.write() {
                Ok(mut local_status) => {
                    let max_length = (1000000 / 10) as usize;
                    datas = local_status.get_timeout_data(max_length);
                    is_delay = datas.len() > 100;
                    false
                }
                Err(_) => {
                    true
                }
            }
        };
        
        if lock_failed {
            // 如果无法获取写锁，等待一段时间后继续
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        
        // 如果没有超时数据，短暂休眠后继续
        if datas.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        for local_data in datas {
            let index = local_data.index;
            let mut value = local_data.v;

            if value.retry >= 5 {
                {
                    match LOCAL_STATUS.write() {
                        Ok(mut local_status) => {
                            match local_status.search_from_index_and_delete(index as u32) {
                                Ok(data) => {
                                    println!("删除失败项:{:?}", data.v);
                                }
                                Err(_) => (),
                            }
                        }
                        Err(_) => (),
                    }
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
            {
                match LOCAL_STATUS.write() {
                    Ok(mut local_status) => {
                        let _ = local_status.search_from_index_and_delete(index);
                        local_status.append(value_c, index);
                    }
                    Err(_) => {}
                }
            }

            let (flag_id, src_port) = send::generate_flag_index_from_map(index as usize);
            let retry_struct = RetryStruct {
                domain: value.domain,
                dns: value.dns,
                src_port,
                flag_id,
                domain_level: value.domain_level as usize,
            };
            
            let _ = retry_send.send(Arc::new(RwLock::new(retry_struct))).unwrap();

            if is_delay {
                let sleep_duration = rand::thread_rng().gen_range(100..=400);
                tokio::time::sleep(Duration::from_micros(sleep_duration)).await;
            }
        }
    }
}

/// 启动重试处理任务
async fn start_retry_handler(
    running: Arc<AtomicBool>,
    senddog: Arc<Mutex<SendDog>>,
    retry_recv: mpsc::Receiver<Arc<RwLock<RetryStruct>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        handle_retry_domains(running, senddog, retry_recv).await;
    })
}

/// 处理重试域名（重用原有逻辑）
async fn handle_retry_domains(
    running: Arc<AtomicBool>,
    senddog: Arc<Mutex<SendDog>>,
    retry_recv: mpsc::Receiver<Arc<RwLock<RetryStruct>>>,
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

/// 等待所有查询完成
async fn wait_for_completion() {
    let start_time = std::time::Instant::now();
    let max_wait_time = Duration::from_secs(300); // 最大等待5分钟
    let mut consecutive_empty_checks = 0;
    let required_consecutive_checks = 5; // 需要连续5次检查都为空才确认完成
    
    loop {
        // 检查是否超时
        if start_time.elapsed() > max_wait_time {
            println!("警告: 等待超时，强制退出等待循环");
            break;
        }
        
        match LOCAL_STATUS.read() {
            Ok(local_status) => {
                if local_status.empty() {
                    consecutive_empty_checks += 1;
                    if consecutive_empty_checks >= required_consecutive_checks {
                        println!("所有查询已完成");
                        break;
                    }
                } else {
                    consecutive_empty_checks = 0;
                }
            }
            Err(_) => {
                println!("警告: 无法读取LOCAL_STATUS，可能发生死锁");
                consecutive_empty_checks += 1;
                if consecutive_empty_checks >= required_consecutive_checks {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(1000)).await
    }
}

/// 运行后处理：验证和DNS解析
async fn run_post_processing(
    discovered_domains: &[String],
    verify_mode: bool,
    resolve_records: bool,
) -> Result<Vec<VerificationResult>, Box<dyn std::error::Error>> {
    let mut verification_results = Vec::new();

    if verify_mode {
        println!("开始HTTP/HTTPS验证...");
        let verifier = DomainVerifier::new(10)?;
        let verify_results = verifier.verify_domains(discovered_domains.to_vec()).await;
        verifier.display_results(&verify_results);
        
        // 转换verify结果为VerificationResult格式
        for result in verify_results {
            let verification_result = VerificationResult {
                domain: result.domain.clone(),
                ip: "N/A".to_string(), // VerifyResult中没有IP字段，使用占位符
                http_status: result.http_status,
                https_status: result.https_status,
                title: result.title.clone(),
                server: result.server_header.clone(),
                is_alive: result.http_alive || result.https_alive,
            };
            
            // 实时打印验证结果
            handle::print_verification_result(&verification_result);
            verification_results.push(verification_result);
        }
    }

    if resolve_records {
        println!("开始DNS记录解析...");
        let resolver = DnsResolver::new().await?;
        let dns_results = resolver.resolve_domains(discovered_domains.to_vec()).await;
        resolver.display_results(&dns_results);
        
        // DNS解析结果不需要添加到verification_results中
        // 因为它们是不同类型的结果
    }

    Ok(verification_results)
}
