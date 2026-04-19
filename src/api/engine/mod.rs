mod build;
mod network;
mod processing;
mod run;
mod runtime;

#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::DnsResolver;
use crate::speed_test::BandwidthLimiter;
use crate::state::BruteForceState;
#[cfg(feature = "verify")]
use crate::verify::DomainVerifier;
use crate::wildcard::WildcardDetector;

use super::SubdomainBruteConfig;

/// 域名暴破引擎
pub struct SubdomainBruteEngine {
    pub(super) config: SubdomainBruteConfig,
    pub(super) wildcard_detector: Option<WildcardDetector>,
    #[cfg(feature = "verify")]
    pub(super) verifier: Option<DomainVerifier>,
    #[cfg(feature = "dns-resolver")]
    pub(super) dns_resolver: Option<DnsResolver>,
    pub(super) _bandwidth_limiter: Option<BandwidthLimiter>,
    pub(super) state: BruteForceState,
}
