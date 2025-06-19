use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::{RecordType, RData};
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::Arc;

/// DNS记录类型
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A(String),           // IPv4地址
    AAAA(String),        // IPv6地址
    CNAME(String),       // 别名
    NS(String),          // 名称服务器
    MX(u16, String),     // 邮件交换器 (优先级, 主机名)
    TXT(String),         // 文本记录
    SOA(String),         // 授权开始
    PTR(String),         // 指针记录
}

/// DNS解析结果
#[derive(Debug, Clone)]
pub struct DnsResolveResult {
    pub domain: String,
    pub records: HashMap<String, Vec<DnsRecord>>,
    pub has_records: bool,
}

/// DNS解析器
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(DnsResolver { resolver })
    }

    /// 解析域名的所有记录类型
    pub async fn resolve_all_records(&self, domain: &str) -> DnsResolveResult {
        let mut records = HashMap::new();
        let mut has_records = false;

        // 解析A记录
        if let Ok(response) = self.resolver.lookup_ip(domain).await {
            let mut a_records = Vec::new();
            for ip in response.iter() {
                match ip {
                    IpAddr::V4(ipv4) => {
                        a_records.push(DnsRecord::A(ipv4.to_string()));
                        has_records = true;
                    }
                    IpAddr::V6(ipv6) => {
                        a_records.push(DnsRecord::AAAA(ipv6.to_string()));
                        has_records = true;
                    }
                }
            }
            if !a_records.is_empty() {
                records.insert("A/AAAA".to_string(), a_records);
            }
        }

        // 解析CNAME记录
        if let Ok(response) = self.resolver.lookup(domain, RecordType::CNAME).await {
            let mut cname_records = Vec::new();
            for record in response.iter() {
                match record {
                    RData::CNAME(cname) => {
                        cname_records.push(DnsRecord::CNAME(cname.to_string()));
                        has_records = true;
                    }
                    _ => {}
                }
            }
            if !cname_records.is_empty() {
                records.insert("CNAME".to_string(), cname_records);
            }
        }

        // 解析NS记录
        if let Ok(response) = self.resolver.lookup(domain, RecordType::NS).await {
            let mut ns_records = Vec::new();
            for record in response.iter() {
                match record {
                    RData::NS(ns) => {
                        ns_records.push(DnsRecord::NS(ns.to_string()));
                        has_records = true;
                    }
                    _ => {}
                }
            }
            if !ns_records.is_empty() {
                records.insert("NS".to_string(), ns_records);
            }
        }

        // 解析MX记录
        if let Ok(response) = self.resolver.lookup(domain, RecordType::MX).await {
            let mut mx_records = Vec::new();
            for record in response.iter() {
                match record {
                    RData::MX(mx) => {
                        mx_records.push(DnsRecord::MX(mx.preference(), mx.exchange().to_string()));
                        has_records = true;
                    }
                    _ => {}
                }
            }
            if !mx_records.is_empty() {
                records.insert("MX".to_string(), mx_records);
            }
        }

        // 解析TXT记录
        if let Ok(response) = self.resolver.lookup(domain, RecordType::TXT).await {
            let mut txt_records = Vec::new();
            for record in response.iter() {
                match record {
                    RData::TXT(txt) => {
                        let txt_data = txt.iter()
                            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                            .collect::<Vec<_>>()
                            .join("");
                        txt_records.push(DnsRecord::TXT(txt_data));
                        has_records = true;
                    }
                    _ => {}
                }
            }
            if !txt_records.is_empty() {
                records.insert("TXT".to_string(), txt_records);
            }
        }

        // 解析SOA记录
        if let Ok(response) = self.resolver.lookup(domain, RecordType::SOA).await {
            let mut soa_records = Vec::new();
            for record in response.iter() {
                match record {
                    RData::SOA(soa) => {
                        soa_records.push(DnsRecord::SOA(format!("{} {}", 
                            soa.mname(), soa.rname())));
                        has_records = true;
                    }
                    _ => {}
                }
            }
            if !soa_records.is_empty() {
                records.insert("SOA".to_string(), soa_records);
            }
        }

        DnsResolveResult {
            domain: domain.to_string(),
            records,
            has_records,
        }
    }

    /// 批量解析域名
    pub async fn resolve_domains(&self, domains: Vec<String>) -> Vec<DnsResolveResult> {
        let mut results = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(20)); // 限制并发数

        let mut tasks = Vec::new();
        for domain in domains {
            let permit = Arc::clone(&semaphore);
            let resolver = self.new_resolver().await;
            
            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                resolver.resolve_all_records(&domain).await
            });
            tasks.push(task);
        }

        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        results
    }

    /// 显示解析结果
    pub fn display_results(&self, results: &[DnsResolveResult]) {
        println!("=== DNS解析结果 ===");
        for result in results {
            if result.has_records {
                println!("域名: {}", result.domain);
                for (record_type, records) in &result.records {
                    println!("  {}:", record_type);
                    for record in records {
                        match record {
                            DnsRecord::A(ip) => println!("    {}", ip),
                            DnsRecord::AAAA(ip) => println!("    {}", ip),
                            DnsRecord::CNAME(cname) => println!("    {}", cname),
                            DnsRecord::NS(ns) => println!("    {}", ns),
                            DnsRecord::MX(priority, host) => println!("    {} {}", priority, host),
                            DnsRecord::TXT(txt) => println!("    \"{}\"", txt),
                            DnsRecord::SOA(soa) => println!("    {}", soa),
                            DnsRecord::PTR(ptr) => println!("    {}", ptr),
                        }
                    }
                }
                println!();
            }
        }
    }

    /// 创建新的解析器实例用于并发
    async fn new_resolver(&self) -> DnsResolver {
        DnsResolver {
            resolver: TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
        }
    }

    /// 简单的A记录解析
    pub async fn resolve_a_record(&self, domain: &str) -> Option<String> {
        if let Ok(response) = self.resolver.lookup_ip(domain).await {
            for ip in response.iter() {
                if let IpAddr::V4(ipv4) = ip {
                    return Some(ipv4.to_string());
                }
            }
        }
        None
    }
} 