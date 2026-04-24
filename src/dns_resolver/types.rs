use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use trust_dns_resolver::TokioAsyncResolver;

/// DNS记录类型
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A(String),
    AAAA(String),
    CNAME(String),
    NS(String),
    MX(u16, String),
    TXT(String),
    SOA(String),
    PTR(String),
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
    pub(super) resolver: TokioAsyncResolver,
    pub(super) ptr_cache: Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
}
