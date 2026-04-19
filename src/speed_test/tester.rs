use log::warn;
use rand::Rng;
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::time::sleep;

use crate::device;
use crate::send::SendDog;
use crate::QueryType;

/// 网速测试结果
#[derive(Debug)]
pub struct SpeedTestResult {
    pub send_rate: u64,
    pub recv_rate: u64,
    pub bandwidth_usage: u64,
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
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_target("8.8.8.8").await
    }

    pub async fn new_with_target(target_ip: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ether = device::auto_get_devices_for_dns(&[target_ip.to_string()])
            .await
            .map_err(|error| format!("无法为测速初始化原始发包网络设备: {}", error))?;
        let mut rng = rand::thread_rng();
        let flag_id = rng.gen_range(400..655);
        let sender = SendDog::new(ether, vec![target_ip.to_string()], flag_id)
            .map_err(|error| format!("无法初始化原始发包器: {}", error))?;

        Ok(SpeedTester {
            sent_packets: Arc::new(AtomicU64::new(0)),
            recv_packets: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            sender: Arc::new(Mutex::new(sender)),
            target_ip: target_ip.to_string(),
        })
    }

    /// 执行网速测试
    pub async fn run_speed_test(&self, duration_secs: u64) -> SpeedTestResult {
        println!("开始网速测试，持续 {} 秒...", duration_secs);
        println!("目标DNS服务器: {}", self.target_ip);

        self.sent_packets.store(0, Ordering::Relaxed);
        self.recv_packets.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);

        let start_time = Instant::now();
        let sent_counter = Arc::clone(&self.sent_packets);
        let bytes_counter = Arc::clone(&self.bytes_sent);
        let sender = Arc::clone(&self.sender);
        let target_ip = self.target_ip.clone();

        tokio::spawn(async move {
            let mut count = 0u64;

            while start_time.elapsed().as_secs() < duration_secs {
                let test_domain = format!("speedtest{}.example.com", count % 1000);
                let src_port = rand::thread_rng().gen_range(10000..65000);
                let flag_id = rand::thread_rng().gen_range(1..100);

                if let Ok(sender_guard) = sender.try_lock() {
                    if let Err(error) = sender_guard.send(
                        test_domain,
                        target_ip.clone(),
                        QueryType::A,
                        src_port,
                        flag_id,
                    ) {
                        warn!("测速发送失败: {}", error);
                    } else {
                        sent_counter.fetch_add(1, Ordering::Relaxed);
                        bytes_counter.fetch_add(64, Ordering::Relaxed);
                        count += 1;
                    }
                }

                if count % 100 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
        });

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

    pub fn record_received_packet(&self) {
        self.recv_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_sent_packet(&self, bytes: u64) {
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn display_result(&self, result: &SpeedTestResult) {
        println!("=== 网速测试结果 ===");
        println!("目标DNS服务器: {}", self.target_ip);
        println!("发包速度: {} 包/秒", result.send_rate);
        println!("收包速度: {} 包/秒", result.recv_rate);
        println!(
            "带宽使用: {} 字节/秒 ({:.2} MB/s)",
            result.bandwidth_usage,
            result.bandwidth_usage as f64 / 1024.0 / 1024.0
        );
    }
}
