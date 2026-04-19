use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::time::sleep;

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

        if last_reset.elapsed().as_secs() >= 1 {
            self.bytes_sent.store(0, Ordering::Relaxed);
            *last_reset = Instant::now();
            return true;
        }

        if current_bytes + packet_size <= self.max_bytes_per_sec {
            self.bytes_sent.fetch_add(packet_size, Ordering::Relaxed);
            true
        } else {
            sleep(Duration::from_millis(100)).await;
            false
        }
    }
}
