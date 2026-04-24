use std::sync::{Arc, Mutex};

use tokio::time::{sleep_until, Duration, Instant};

/// 带宽限制器
#[derive(Clone)]
pub struct BandwidthLimiter {
    max_bytes_per_sec: u64,
    next_available_at: Arc<Mutex<Instant>>,
}

impl BandwidthLimiter {
    pub fn new(max_bytes_per_sec: u64) -> Self {
        BandwidthLimiter {
            max_bytes_per_sec,
            next_available_at: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// 申请发送额度，按时间连续平滑限速，避免一秒窗口内的瞬时突发
    pub async fn acquire(&self, packet_size: u64) {
        let send_interval = duration_for_packet(packet_size, self.max_bytes_per_sec);
        let reserved_at = {
            let mut next_available_at = self.next_available_at.lock().unwrap();
            let now = Instant::now();
            let reserved_at = (*next_available_at).max(now);
            *next_available_at = reserved_at + send_interval;
            reserved_at
        };

        if reserved_at > Instant::now() {
            sleep_until(reserved_at).await;
        }
    }
}

fn duration_for_packet(packet_size: u64, max_bytes_per_sec: u64) -> Duration {
    let nanos = ((packet_size as u128) * 1_000_000_000u128).div_ceil(max_bytes_per_sec as u128);
    Duration::from_nanos(nanos.max(1) as u64)
}

#[cfg(test)]
mod tests {
    use super::{duration_for_packet, BandwidthLimiter};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn acquire_spaces_packets_by_reserved_interval() {
        let limiter = BandwidthLimiter::new(100);
        limiter.acquire(50).await;

        let waiting_limiter = limiter.clone();
        let handle = tokio::spawn(async move {
            waiting_limiter.acquire(1).await;
        });

        tokio::task::yield_now().await;
        assert!(!handle.is_finished());

        tokio::time::advance(Duration::from_millis(499)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        handle.await.unwrap();
    }

    #[test]
    fn duration_for_packet_matches_rate() {
        assert_eq!(duration_for_packet(64, 64), Duration::from_secs(1));
        assert_eq!(duration_for_packet(32, 64), Duration::from_millis(500));
        assert_eq!(
            duration_for_packet(1, 1_000_000),
            Duration::from_nanos(1_000)
        );
    }
}
