use log::warn;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::proto::rr::{RData, RecordType};
use trust_dns_resolver::TokioAsyncResolver;

use crate::dns_resolver::config::build_resolver_config;
use crate::dns_resolver::{DnsRecord, DnsResolveResult, DnsResolver};

impl DnsResolver {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_resolvers(&[]).await
    }

    pub async fn new_with_resolvers(
        resolvers: &[String],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let resolver =
            TokioAsyncResolver::tokio(build_resolver_config(resolvers)?, ResolverOpts::default());
        Ok(DnsResolver { resolver })
    }

    /// 解析域名的所有记录类型
    pub async fn resolve_all_records(&self, domain: &str) -> DnsResolveResult {
        resolve_all_records_with(&self.resolver, domain).await
    }

    /// 批量解析域名
    pub async fn resolve_domains(&self, domains: Vec<String>) -> Vec<DnsResolveResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(20));
        let mut tasks = Vec::new();

        for domain in domains {
            let permit = Arc::clone(&semaphore);
            let resolver = self.resolver.clone();

            let task = tokio::spawn(async move {
                match permit.acquire().await {
                    Ok(_permit) => resolve_all_records_with(&resolver, &domain).await,
                    Err(error) => {
                        warn!("获取 DNS 解析信号量失败: {}", error);
                        empty_result(domain)
                    }
                }
            });
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }
        results
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

async fn resolve_all_records_with(resolver: &TokioAsyncResolver, domain: &str) -> DnsResolveResult {
    let mut records = HashMap::new();
    let mut has_records = false;

    let aaaa_records = lookup_a_and_aaaa(resolver, domain, &mut has_records).await;
    insert_records(&mut records, "A/AAAA", aaaa_records);

    let cname_records =
        lookup_record_set(resolver, domain, RecordType::CNAME, |record| match record {
            RData::CNAME(cname) => Some(DnsRecord::CNAME(cname.to_string())),
            _ => None,
        })
        .await;
    has_records |= !cname_records.is_empty();
    insert_records(&mut records, "CNAME", cname_records);

    let ns_records = lookup_record_set(resolver, domain, RecordType::NS, |record| match record {
        RData::NS(ns) => Some(DnsRecord::NS(ns.to_string())),
        _ => None,
    })
    .await;
    has_records |= !ns_records.is_empty();
    insert_records(&mut records, "NS", ns_records);

    let mx_records = lookup_record_set(resolver, domain, RecordType::MX, |record| match record {
        RData::MX(mx) => Some(DnsRecord::MX(mx.preference(), mx.exchange().to_string())),
        _ => None,
    })
    .await;
    has_records |= !mx_records.is_empty();
    insert_records(&mut records, "MX", mx_records);

    let txt_records = lookup_record_set(resolver, domain, RecordType::TXT, |record| match record {
        RData::TXT(txt) => Some(DnsRecord::TXT(
            txt.iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect::<Vec<_>>()
                .join(""),
        )),
        _ => None,
    })
    .await;
    has_records |= !txt_records.is_empty();
    insert_records(&mut records, "TXT", txt_records);

    let soa_records = lookup_record_set(resolver, domain, RecordType::SOA, |record| match record {
        RData::SOA(soa) => Some(DnsRecord::SOA(format!("{} {}", soa.mname(), soa.rname()))),
        _ => None,
    })
    .await;
    has_records |= !soa_records.is_empty();
    insert_records(&mut records, "SOA", soa_records);

    DnsResolveResult {
        domain: domain.to_string(),
        records,
        has_records,
    }
}

async fn lookup_a_and_aaaa(
    resolver: &TokioAsyncResolver,
    domain: &str,
    has_records: &mut bool,
) -> Vec<DnsRecord> {
    let mut records = Vec::new();
    if let Ok(response) = resolver.lookup_ip(domain).await {
        for ip in response.iter() {
            match ip {
                IpAddr::V4(ipv4) => {
                    records.push(DnsRecord::A(ipv4.to_string()));
                    *has_records = true;
                }
                IpAddr::V6(ipv6) => {
                    records.push(DnsRecord::AAAA(ipv6.to_string()));
                    *has_records = true;
                }
            }
        }
    }
    records
}

async fn lookup_record_set<F>(
    resolver: &TokioAsyncResolver,
    domain: &str,
    record_type: RecordType,
    mut map_record: F,
) -> Vec<DnsRecord>
where
    F: FnMut(&RData) -> Option<DnsRecord>,
{
    let mut records = Vec::new();
    if let Ok(response) = resolver.lookup(domain, record_type).await {
        for record in response.iter() {
            if let Some(record) = map_record(record) {
                records.push(record);
            }
        }
    }
    records
}

fn insert_records(
    records: &mut HashMap<String, Vec<DnsRecord>>,
    key: &str,
    values: Vec<DnsRecord>,
) {
    if !values.is_empty() {
        records.insert(key.to_string(), values);
    }
}

fn empty_result(domain: String) -> DnsResolveResult {
    DnsResolveResult {
        domain,
        records: HashMap::new(),
        has_records: false,
    }
}
