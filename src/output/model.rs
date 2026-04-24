use std::collections::HashMap;

use crate::api::SubdomainResult;
#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::{DnsRecord, DnsResolveResult};
use crate::handle::{
    AggregatedDiscoveredDomain, AggregatedRecordValues, CdnEvidence, DiscoveredDomain,
    SummaryStats, VerificationResult,
};
#[cfg(feature = "verify")]
use crate::verify::VerifyResult;
use serde::{Deserialize, Serialize};

/// 可序列化的发现域名结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDiscoveredDomain {
    pub domain: String,
    pub value: String,
    pub query_type: String,
    pub record_type: String,
    pub timestamp: u64,
    pub formatted_time: String,
}

/// 可序列化的验证结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableVerificationResult {
    pub domain: String,
    pub ip: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub is_alive: bool,
}

/// 可序列化的聚合记录结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAggregatedRecordValues {
    pub record_type: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableCdnEvidence {
    pub source: String,
    pub value: String,
    pub detail: String,
}

/// 可序列化的聚合域名结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAggregatedDiscoveredDomain {
    pub domain: String,
    pub records: Vec<SerializableAggregatedRecordValues>,
    pub has_cdn: bool,
    pub possible_cdn: bool,
    pub cdn_provider: Option<String>,
    pub cdn_confidence: Option<String>,
    pub cdn_evidence: Vec<SerializableCdnEvidence>,
    pub cdn_signals: Vec<SerializableCdnEvidence>,
    pub raw_record_count: usize,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// 可序列化的详细验证结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableVerifyDetail {
    pub domain: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub http_alive: bool,
    pub https_alive: bool,
    pub redirect_url: Option<String>,
    pub server_header: Option<String>,
    pub title: Option<String>,
}

/// 可序列化的DNS解析结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDnsResolveResult {
    pub domain: String,
    pub has_records: bool,
    pub records: HashMap<String, Vec<String>>,
}

/// 可序列化的原始扫描结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSubdomainResult {
    pub domain: String,
    pub value: String,
    pub query_type: String,
    pub record_type: String,
    pub timestamp: u64,
    pub formatted_time: String,
    pub verified: Option<SerializableVerifyDetail>,
    pub dns_records: Option<SerializableDnsResolveResult>,
}

/// 可序列化的汇总统计结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSummaryStats {
    pub total_domains: usize,
    pub unique_domains: usize,
    pub unique_ips: Vec<String>,
    pub ip_ranges: std::collections::HashMap<String, Vec<String>>,
    pub record_types: std::collections::HashMap<String, usize>,
    pub cdn_domains: usize,
    pub suspected_cdn_domains: usize,
    pub cdn_providers: std::collections::HashMap<String, usize>,
    pub cdn_confidence: std::collections::HashMap<String, usize>,
    pub verified_domains: usize,
    pub alive_domains: usize,
}

/// 完整的导出数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    pub raw_results: Vec<SerializableSubdomainResult>,
    pub discovered_domains: Vec<SerializableDiscoveredDomain>,
    pub aggregated_domains: Vec<SerializableAggregatedDiscoveredDomain>,
    pub verification_results: Vec<SerializableVerificationResult>,
    pub summary: SerializableSummaryStats,
    pub export_time: String,
}

impl From<DiscoveredDomain> for SerializableDiscoveredDomain {
    fn from(domain: DiscoveredDomain) -> Self {
        let formatted_time = chrono::DateTime::from_timestamp(domain.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        SerializableDiscoveredDomain {
            domain: domain.domain,
            value: domain.value,
            query_type: domain.query_type.to_string(),
            record_type: domain.record_type,
            timestamp: domain.timestamp,
            formatted_time,
        }
    }
}

impl From<VerificationResult> for SerializableVerificationResult {
    fn from(result: VerificationResult) -> Self {
        SerializableVerificationResult {
            domain: result.domain,
            ip: result.ip,
            http_status: result.http_status,
            https_status: result.https_status,
            title: result.title,
            server: result.server,
            is_alive: result.is_alive,
        }
    }
}

impl From<AggregatedRecordValues> for SerializableAggregatedRecordValues {
    fn from(record: AggregatedRecordValues) -> Self {
        SerializableAggregatedRecordValues {
            record_type: record.record_type,
            values: record.values,
        }
    }
}

impl From<CdnEvidence> for SerializableCdnEvidence {
    fn from(evidence: CdnEvidence) -> Self {
        Self {
            source: evidence.source,
            value: evidence.value,
            detail: evidence.detail,
        }
    }
}

impl From<AggregatedDiscoveredDomain> for SerializableAggregatedDiscoveredDomain {
    fn from(domain: AggregatedDiscoveredDomain) -> Self {
        SerializableAggregatedDiscoveredDomain {
            domain: domain.domain,
            records: domain.records.into_iter().map(Into::into).collect(),
            has_cdn: domain.has_cdn,
            possible_cdn: domain.possible_cdn,
            cdn_provider: domain.cdn_provider,
            cdn_confidence: domain.cdn_confidence.map(|value| value.to_string()),
            cdn_evidence: domain.cdn_evidence.into_iter().map(Into::into).collect(),
            cdn_signals: domain.cdn_signals.into_iter().map(Into::into).collect(),
            raw_record_count: domain.raw_record_count,
            first_seen: domain.first_seen,
            last_seen: domain.last_seen,
        }
    }
}

#[cfg(feature = "verify")]
impl From<VerifyResult> for SerializableVerifyDetail {
    fn from(result: VerifyResult) -> Self {
        SerializableVerifyDetail {
            domain: result.domain,
            http_status: result.http_status,
            https_status: result.https_status,
            http_alive: result.http_alive,
            https_alive: result.https_alive,
            redirect_url: result.redirect_url,
            server_header: result.server_header,
            title: result.title,
        }
    }
}

#[cfg(feature = "dns-resolver")]
impl From<DnsResolveResult> for SerializableDnsResolveResult {
    fn from(result: DnsResolveResult) -> Self {
        SerializableDnsResolveResult {
            domain: result.domain,
            has_records: result.has_records,
            records: result
                .records
                .into_iter()
                .map(|(record_type, values)| {
                    (
                        record_type,
                        values.into_iter().map(stringify_dns_record).collect(),
                    )
                })
                .collect(),
        }
    }
}

impl From<SubdomainResult> for SerializableSubdomainResult {
    fn from(result: SubdomainResult) -> Self {
        let formatted_time = chrono::DateTime::from_timestamp(result.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        SerializableSubdomainResult {
            domain: result.domain,
            value: result.value,
            query_type: result.query_type.to_string(),
            record_type: result.record_type,
            timestamp: result.timestamp,
            formatted_time,
            #[cfg(feature = "verify")]
            verified: result.verified.map(Into::into),
            #[cfg(not(feature = "verify"))]
            verified: None,
            #[cfg(feature = "dns-resolver")]
            dns_records: result.dns_records.map(Into::into),
            #[cfg(not(feature = "dns-resolver"))]
            dns_records: None,
        }
    }
}

impl From<SummaryStats> for SerializableSummaryStats {
    fn from(stats: SummaryStats) -> Self {
        SerializableSummaryStats {
            total_domains: stats.total_domains,
            unique_domains: stats.unique_domains,
            unique_ips: stats.unique_ips.into_iter().collect(),
            ip_ranges: stats.ip_ranges,
            record_types: stats.record_types,
            cdn_domains: stats.cdn_domains,
            suspected_cdn_domains: stats.suspected_cdn_domains,
            cdn_providers: stats.cdn_providers,
            cdn_confidence: stats.cdn_confidence,
            verified_domains: stats.verified_domains,
            alive_domains: stats.alive_domains,
        }
    }
}

#[cfg(feature = "dns-resolver")]
fn stringify_dns_record(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(ip) => ip,
        DnsRecord::AAAA(ip) => ip,
        DnsRecord::CNAME(cname) => cname,
        DnsRecord::NS(ns) => ns,
        DnsRecord::MX(priority, host) => format!("{} {}", priority, host),
        DnsRecord::TXT(txt) => txt,
        DnsRecord::SOA(soa) => soa,
        DnsRecord::PTR(ptr) => ptr,
    }
}

#[cfg(test)]
mod tests {
    use super::SerializableSubdomainResult;
    use crate::{QueryType, SubdomainResult};

    #[test]
    fn subdomain_result_conversion_preserves_query_type() {
        let result = SubdomainResult {
            domain: "www.example.com".to_string(),
            value: "1.1.1.1".to_string(),
            query_type: QueryType::Aaaa,
            record_type: "AAAA".to_string(),
            timestamp: 1,
            #[cfg(feature = "verify")]
            verified: None,
            #[cfg(feature = "dns-resolver")]
            dns_records: None,
        };

        let serializable = SerializableSubdomainResult::from(result);

        assert_eq!(serializable.query_type, "AAAA");
        assert_eq!(serializable.value, "1.1.1.1");
        assert_eq!(serializable.record_type, "AAAA");
        assert_eq!(serializable.formatted_time, "1970-01-01 00:00:01");
    }
}
