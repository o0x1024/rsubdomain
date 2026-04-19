mod limiter;
#[cfg(feature = "speed-test")]
mod tester;

pub use limiter::BandwidthLimiter;
#[cfg(feature = "speed-test")]
pub use tester::{SpeedTestResult, SpeedTester};
