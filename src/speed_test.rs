use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use crate::send::SendDog;
use crate::device;
use std::sync::Mutex;
use rand::Rng;

/// 网速测试结果
#[derive(Debug)]
pub struct SpeedTestResult {
    pub send_rate: u64,      // 发包速度 (包/秒)
    pub recv_rate: u64,      // 收包速度 (包/秒)
    pub bandwidth_usage: u64, // 带宽使用 (字节/秒)
}

/// 网速测试器
pub struct SpeedTester {
    sent_packets: Arc<AtomicU64>,
    recv_packets: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    sender: Arc<Mutex<SendDog>>,
    target_ip: String,
}

impl SpeedTester {
    pub fn new() -> Self {
        Self::new_with_target("8.8.8.8")
    }

    pub fn new_with_target(target_ip: &str) -> Self {
        let ether = device::auto_get_devices();
        let mut rng = rand::thread_rng();
        let flag_id = rng.gen_range(400..655);
        
        // 使用指定的目标IP作为DNS服务器
        let dns_servers = vec![target_ip.to_string()];
        let sender = SendDog::new(ether, dns_servers, flag_id);
        
        SpeedTester {
            sent_packets: Arc::new(AtomicU64::new(0)),
            recv_packets: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            sender: Arc::new(Mutex::new(sender)),
            target_ip: target_ip.to_string(),
        }
    }

    /// 执行网速测试
    pub async fn run_speed_test(&self, duration_secs: u64) -> SpeedTestResult {
        println!("开始网速测试，持续 {} 秒...", duration_secs);
        println!("目标DNS服务器: {}", self.target_ip);
        
        // 重置计数器
        self.sent_packets.store(0, Ordering::Relaxed);
        self.recv_packets.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);

        let start_time = Instant::now();
        
        // 启动实际发送DNS包的测试任务
        let sent_counter = Arc::clone(&self.sent_packets);
        let bytes_counter = Arc::clone(&self.bytes_sent);
        let sender = Arc::clone(&self.sender);
        let target_ip = self.target_ip.clone();
        
        tokio::spawn(async move {
            let mut count = 0u64;
            
            while start_time.elapsed().as_secs() < duration_secs {
                // 生成随机测试域名
                let test_domain = format!("speedtest{}.example.com", count % 1000);
                let src_port = rand::thread_rng().gen_range(10000..65000);
                let flag_id = rand::thread_rng().gen_range(1..100);
                
                // 实际发送DNS查询包
                if let Ok(sender_guard) = sender.try_lock() {
                    sender_guard.send(test_domain, target_ip.clone(), src_port, flag_id);
                    
                    // 记录发送统计
                    sent_counter.fetch_add(1, Ordering::Relaxed);
                    bytes_counter.fetch_add(64, Ordering::Relaxed); // DNS包大约64字节
                    count += 1;
                }
                
                // 控制发送频率，避免过度消耗CPU
                if count % 100 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
        });

        // 等待测试完成
        sleep(Duration::from_secs(duration_secs)).await;

        let elapsed = start_time.elapsed().as_secs();
        let sent = self.sent_packets.load(Ordering::Relaxed);
        let recv = self.recv_packets.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);

        SpeedTestResult {
            send_rate: sent / elapsed.max(1),
            recv_rate: recv / elapsed.max(1),
            bandwidth_usage: bytes / elapsed.max(1),
        }
    }

    /// 记录接收到的包
    pub fn record_received_packet(&self) {
        self.recv_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录发送的包
    pub fn record_sent_packet(&self, bytes: u64) {
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 显示测试结果
    pub fn display_result(&self, result: &SpeedTestResult) {
        println!("=== 网速测试结果 ===");
        println!("目标DNS服务器: {}", self.target_ip);
        println!("发包速度: {} 包/秒", result.send_rate);
        println!("收包速度: {} 包/秒", result.recv_rate);
        println!("带宽使用: {} 字节/秒 ({:.2} MB/s)", 
                result.bandwidth_usage, 
                result.bandwidth_usage as f64 / 1024.0 / 1024.0);
    }
}

/// 带宽限制器
pub struct BandwidthLimiter {
    max_bytes_per_sec: u64,
    bytes_sent: Arc<AtomicU64>,
    last_reset: Arc<std::sync::Mutex<Instant>>,
}

impl BandwidthLimiter {
    pub fn new(max_bytes_per_sec: u64) -> Self {
        BandwidthLimiter {
            max_bytes_per_sec,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            last_reset: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// 检查是否可以发送数据包
    pub async fn can_send(&self, packet_size: u64) -> bool {
        let current_bytes = self.bytes_sent.load(Ordering::Relaxed);
        let mut last_reset = self.last_reset.lock().unwrap();
        
        // 每秒重置计数器
        if last_reset.elapsed().as_secs() >= 1 {
            self.bytes_sent.store(0, Ordering::Relaxed);
            *last_reset = Instant::now();
            return true;
        }

        if current_bytes + packet_size <= self.max_bytes_per_sec {
            self.bytes_sent.fetch_add(packet_size, Ordering::Relaxed);
            true
        } else {
            // 需要等待
            let wait_time = Duration::from_millis(100);
            sleep(wait_time).await;
            false
        }
    }
} 