#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::DnsResolver;
#[cfg(feature = "verify")]
use crate::verify::DomainVerifier;
use crate::wildcard::WildcardDetector;

use super::SubdomainBruteEngine;
use crate::api::SubdomainBruteConfig;
use crate::state::BruteForceState;

impl SubdomainBruteEngine {
    /// 创建新的暴破引擎
    pub async fn new(config: SubdomainBruteConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let wildcard_detector = if config.skip_wildcard {
            None
        } else {
            Some(WildcardDetector::new_with_resolvers(&config.resolvers).await?)
        };

        #[cfg(feature = "verify")]
        let verifier = if config.verify_mode {
            Some(DomainVerifier::new(
                config.verify_timeout_seconds,
                config.verify_concurrency,
            )?)
        } else {
            None
        };
        #[cfg(not(feature = "verify"))]
        if config.verify_mode {
            return Err("当前构建未启用 verify feature，无法进行 HTTP/HTTPS 验证".into());
        }

        #[cfg(feature = "dns-resolver")]
        let dns_resolver = if config.resolve_records {
            Some(DnsResolver::new_with_resolvers(&config.resolvers).await?)
        } else {
            None
        };
        #[cfg(not(feature = "dns-resolver"))]
        if config.resolve_records {
            return Err("当前构建未启用 dns-resolver feature，无法解析 DNS 记录".into());
        }

        Ok(SubdomainBruteEngine {
            _bandwidth_limiter: Self::create_bandwidth_limiter(config.bandwidth_limit.as_deref())?,
            config,
            wildcard_detector,
            #[cfg(feature = "verify")]
            verifier,
            #[cfg(feature = "dns-resolver")]
            dns_resolver,
            state: BruteForceState::new(),
        })
    }
}
