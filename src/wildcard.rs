use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use rand::Rng;

/// 泛解析检测器
pub struct WildcardDetector {
    resolver: TokioAsyncResolver,
    wildcard_cache: Arc<Mutex<HashMap<String, Vec<Ipv4Addr>>>>,
}

impl WildcardDetector {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(WildcardDetector {
            resolver,
            wildcard_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 检测域名是否存在泛解析
    pub async fn detect_wildcard(&self, domain: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // 生成随机子域名进行测试
        let test_subdomains = self.generate_test_subdomains(domain, 3);
        let mut wildcard_ips = Vec::new();

        for test_domain in &test_subdomains {
            match self.resolver.lookup_ip(test_domain.as_str()).await {
                Ok(response) => {
                    let ips: Vec<Ipv4Addr> = response
                        .iter()
                        .filter_map(|ip| {
                            if let std::net::IpAddr::V4(ipv4) = ip {
                                Some(ipv4)
                            } else {
                                None
                            }
                        })
                        .collect();
                    
                    if !ips.is_empty() {
                        wildcard_ips.extend(ips);
                    }
                }
                Err(_) => {
                    // 如果随机域名无法解析，说明不存在泛解析
                    continue;
                }
            }
        }

        // 如果所有测试域名都返回相同的IP，则认为存在泛解析
        if wildcard_ips.len() >= 2 {
            let first_ip = wildcard_ips[0];
            let is_wildcard = wildcard_ips.iter().all(|&ip| ip == first_ip);
            
            if is_wildcard {
                // 缓存泛解析IP
                let mut cache = self.wildcard_cache.lock().unwrap();
                cache.insert(domain.to_string(), vec![first_ip]);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 检查域名是否为泛解析结果
    pub fn is_wildcard_result(&self, domain: &str, ip: &Ipv4Addr) -> bool {
        let cache = self.wildcard_cache.lock().unwrap();
        let root_domain = self.extract_root_domain(domain);
        
        if let Some(wildcard_ips) = cache.get(&root_domain) {
            return wildcard_ips.contains(ip);
        }
        false
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

    /// 提取根域名
    fn extract_root_domain(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        }
    }
} 