use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::QueryType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdnConfidence {
    Low,
    Medium,
    High,
}

impl CdnConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            CdnConfidence::Low => "low",
            CdnConfidence::Medium => "medium",
            CdnConfidence::High => "high",
        }
    }
}

impl fmt::Display for CdnConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnEvidence {
    pub source: String,
    pub value: String,
    pub detail: String,
}

/// 发现的域名结果
#[derive(Debug, Clone)]
pub struct DiscoveredDomain {
    pub domain: String,
    pub value: String,
    pub query_type: QueryType,
    pub record_type: String,
    pub timestamp: u64,
}

/// 按域名聚合后的记录集合
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedRecordValues {
    pub record_type: String,
    pub values: Vec<String>,
}

/// 按域名聚合后的发现结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedDiscoveredDomain {
    pub domain: String,
    pub records: Vec<AggregatedRecordValues>,
    pub has_cdn: bool,
    pub possible_cdn: bool,
    pub cdn_provider: Option<String>,
    pub cdn_confidence: Option<CdnConfidence>,
    pub cdn_evidence: Vec<CdnEvidence>,
    pub cdn_signals: Vec<CdnEvidence>,
    pub raw_record_count: usize,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// 验证结果
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub domain: String,
    pub ip: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub is_alive: bool,
}

/// 汇总统计信息
#[derive(Debug, Clone)]
pub struct SummaryStats {
    pub total_domains: usize,
    pub unique_domains: usize,
    pub unique_ips: HashSet<String>,
    pub ip_ranges: HashMap<String, Vec<String>>,
    pub record_types: HashMap<String, usize>,
    pub cdn_domains: usize,
    pub suspected_cdn_domains: usize,
    pub cdn_providers: HashMap<String, usize>,
    pub cdn_confidence: HashMap<String, usize>,
    pub verified_domains: usize,
    pub alive_domains: usize,
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}",
            self.domain,
            self.ip,
            self.http_status
                .map_or("N/A".to_string(), |status| status.to_string()),
            self.https_status
                .map_or("N/A".to_string(), |status| status.to_string()),
            self.title.as_deref().unwrap_or("N/A"),
            if self.is_alive { "YES" } else { "NO" }
        )
    }
}
