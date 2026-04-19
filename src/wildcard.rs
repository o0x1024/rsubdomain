use log::warn;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

/// 泛解析检测器
pub struct WildcardDetector {
    resolver: TokioAsyncResolver,
    wildcard_cache: Arc<Mutex<HashMap<String, Vec<Ipv4Addr>>>>,
}

impl WildcardDetector {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_resolvers(&[]).await
    }

    pub async fn new_with_resolvers(
        resolvers: &[String],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let resolver =
            TokioAsyncResolver::tokio(build_resolver_config(resolvers)?, ResolverOpts::default());
        Ok(WildcardDetector {
            resolver,
            wildcard_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 检测域名是否存在泛解析
    pub async fn detect_wildcard(&self, domain: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let test_subdomains = self.generate_test_subdomains(domain, 3);
        let mut answer_sets = Vec::new();

        for test_domain in &test_subdomains {
            let ips: HashSet<Ipv4Addr> = match self.resolver.lookup_ip(test_domain.as_str()).await {
                Ok(response) => response
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(ipv4) => Some(ipv4),
                        IpAddr::V6(_) => None,
                    })
                    .collect(),
                Err(_) => HashSet::new(),
            };

            if ips.is_empty() {
                return Ok(false);
            }

            answer_sets.push(ips);
        }

        let mut common_ips = match answer_sets.first() {
            Some(ips) => ips.clone(),
            None => return Ok(false),
        };

        for ips in answer_sets.iter().skip(1) {
            common_ips.retain(|ip| ips.contains(ip));
            if common_ips.is_empty() {
                return Ok(false);
            }
        }

        match self.wildcard_cache.lock() {
            Ok(mut cache) => {
                cache.insert(domain.to_string(), common_ips.into_iter().collect());
            }
            Err(error) => warn!("wildcard_cache lock 被 poison: {}", error),
        }

        Ok(true)
    }

    /// 检查域名是否为泛解析结果
    pub fn is_wildcard_result(&self, domain: &str, ip: &Ipv4Addr) -> bool {
        match self.wildcard_cache.lock() {
            Ok(cache) => cache.iter().any(|(base_domain, wildcard_ips)| {
                belongs_to_base_domain(domain, base_domain) && wildcard_ips.contains(ip)
            }),
            Err(error) => {
                warn!("wildcard_cache lock 被 poison: {}", error);
                false
            }
        }
    }

    /// 生成测试用的随机子域名
    fn generate_test_subdomains(&self, domain: &str, count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let mut test_domains = Vec::new();

        for _ in 0..count {
            let random_str: String = (0..10)
                .map(|_| {
                    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
                    chars[rng.gen_range(0..chars.len())] as char
                })
                .collect();

            test_domains.push(format!("{}.{}", random_str, domain));
        }

        test_domains
    }
}

fn build_resolver_config(
    resolvers: &[String],
) -> Result<ResolverConfig, Box<dyn std::error::Error>> {
    let ips: Vec<IpAddr> = resolvers
        .iter()
        .map(|resolver| resolver.parse())
        .collect::<Result<Vec<IpAddr>, _>>()?;

    if ips.is_empty() {
        return Ok(ResolverConfig::default());
    }

    Ok(ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&ips, 53, true),
    ))
}

fn belongs_to_base_domain(domain: &str, base_domain: &str) -> bool {
    domain == base_domain || domain.ends_with(&format!(".{}", base_domain))
}
