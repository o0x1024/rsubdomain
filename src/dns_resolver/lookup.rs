use log::warn;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
        Ok(DnsResolver {
            resolver,
            ptr_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 解析域名的所有记录类型
    pub async fn resolve_all_records(&self, domain: &str) -> DnsResolveResult {
        resolve_all_records_with(&self.resolver, &self.ptr_cache, domain).await
    }

    /// 批量解析域名
    pub async fn resolve_domains(&self, domains: Vec<String>) -> Vec<DnsResolveResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(20));
        let mut tasks = Vec::new();

        for domain in domains {
            let permit = Arc::clone(&semaphore);
            let resolver = self.resolver.clone();
            let ptr_cache = Arc::clone(&self.ptr_cache);

            let task = tokio::spawn(async move {
                match permit.acquire().await {
                    Ok(_permit) => resolve_all_records_with(&resolver, &ptr_cache, &domain).await,
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
        let records = lookup_record_set(
            &self.resolver,
            domain,
            RecordType::A,
            |record| match record {
                RData::A(ipv4) => Some(DnsRecord::A(ipv4.to_string())),
                _ => None,
            },
        )
        .await;

        for record in records {
            if let DnsRecord::A(ipv4) = record {
                return Some(ipv4);
            }
        }
        None
    }
}

async fn resolve_all_records_with(
    resolver: &TokioAsyncResolver,
    ptr_cache: &Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
    domain: &str,
) -> DnsResolveResult {
    let mut records = HashMap::new();
    let mut has_records = false;

    let cname_records =
        lookup_record_set(resolver, domain, RecordType::CNAME, |record| match record {
            RData::CNAME(cname) => Some(DnsRecord::CNAME(cname.to_string())),
            _ => None,
        })
        .await;
    has_records |= !cname_records.is_empty();
    insert_records(&mut records, "CNAME", cname_records);
    if has_records {
        return DnsResolveResult {
            domain: domain.to_string(),
            records,
            has_records,
        };
    }

    let a_records = lookup_record_set(resolver, domain, RecordType::A, |record| match record {
        RData::A(ipv4) => Some(DnsRecord::A(ipv4.to_string())),
        _ => None,
    })
    .await;
    has_records |= !a_records.is_empty();
    insert_records(&mut records, "A", a_records);

    let aaaa_records =
        lookup_record_set(resolver, domain, RecordType::AAAA, |record| match record {
            RData::AAAA(ipv6) => Some(DnsRecord::AAAA(ipv6.to_string())),
            _ => None,
        })
        .await;
    has_records |= !aaaa_records.is_empty();
    insert_records(&mut records, "AAAA", aaaa_records);

    let ptr_records =
        lookup_ptr_records(resolver, ptr_cache, records.get("A"), records.get("AAAA")).await;
    has_records |= !ptr_records.is_empty();
    insert_records(&mut records, "PTR", ptr_records);

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

async fn lookup_ptr_records(
    resolver: &TokioAsyncResolver,
    ptr_cache: &Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
    a_records: Option<&Vec<DnsRecord>>,
    aaaa_records: Option<&Vec<DnsRecord>>,
) -> Vec<DnsRecord> {
    let mut ptr_records = Vec::new();
    let mut ip_candidates = Vec::new();

    if let Some(records) = a_records {
        for record in records {
            if let DnsRecord::A(ip) = record {
                ip_candidates.push(ip.clone());
            }
        }
    }

    if let Some(records) = aaaa_records {
        for record in records {
            if let DnsRecord::AAAA(ip) = record {
                ip_candidates.push(ip.clone());
            }
        }
    }

    ip_candidates.sort();
    ip_candidates.dedup();

    for ip_candidate in ip_candidates {
        let ip = match ip_candidate.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        if let Ok(cache) = ptr_cache.lock() {
            if let Some(cached) = cache.get(&ip) {
                for value in cached {
                    ptr_records.push(DnsRecord::PTR(value.clone()));
                }
                continue;
            }
        }

        let mut resolved_values = Vec::new();
        if let Ok(response) = resolver.reverse_lookup(ip).await {
            for ptr in response.iter() {
                let value = ptr.to_string();
                ptr_records.push(DnsRecord::PTR(value.clone()));
                resolved_values.push(value);
            }
        }

        if let Ok(mut cache) = ptr_cache.lock() {
            cache.insert(ip, resolved_values);
        }
    }

    ptr_records
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::dns_resolver::{DnsRecord, DnsResolveResult};

    fn build_direct_record_result(
        domain: &str,
        cname_records: Vec<DnsRecord>,
        a_records: Vec<DnsRecord>,
        aaaa_records: Vec<DnsRecord>,
        txt_records: Vec<DnsRecord>,
    ) -> DnsResolveResult {
        let mut records = HashMap::new();
        let mut has_records = false;

        has_records |= !cname_records.is_empty();
        super::insert_records(&mut records, "CNAME", cname_records);
        if has_records {
            return DnsResolveResult {
                domain: domain.to_string(),
                records,
                has_records,
            };
        }

        has_records |= !a_records.is_empty();
        super::insert_records(&mut records, "A", a_records);

        has_records |= !aaaa_records.is_empty();
        super::insert_records(&mut records, "AAAA", aaaa_records);

        has_records |= !txt_records.is_empty();
        super::insert_records(&mut records, "TXT", txt_records);

        DnsResolveResult {
            domain: domain.to_string(),
            records,
            has_records,
        }
    }

    #[test]
    fn cname_result_stops_direct_record_expansion() {
        let result = build_direct_record_result(
            "m.mgtv.com",
            vec![DnsRecord::CNAME("m.mgtv.com.cdn.dnsv1.com".to_string())],
            vec![DnsRecord::A("58.49.196.112".to_string())],
            Vec::new(),
            vec![DnsRecord::TXT("ignored".to_string())],
        );

        assert!(result.has_records);
        assert_eq!(result.records.len(), 1);
        assert!(result.records.contains_key("CNAME"));
        assert!(!result.records.contains_key("A"));
        assert!(!result.records.contains_key("TXT"));
    }

    #[test]
    fn non_cname_result_preserves_multi_value_records() {
        let result = build_direct_record_result(
            "app.mgtv.com",
            Vec::new(),
            vec![
                DnsRecord::A("119.96.61.143".to_string()),
                DnsRecord::A("119.96.61.144".to_string()),
            ],
            vec![DnsRecord::AAAA("2400::1".to_string())],
            vec![DnsRecord::TXT("v=spf1".to_string())],
        );

        assert!(result.has_records);
        assert_eq!(result.records["A"].len(), 2);
        assert_eq!(result.records["AAAA"].len(), 1);
        assert_eq!(result.records["TXT"].len(), 1);
    }
}
