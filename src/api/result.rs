#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::DnsResolveResult;
use crate::handle::{
    generate_summary_from_data, AggregatedDiscoveredDomain, AggregatedRecordValues,
    DiscoveredDomain, SummaryStats, VerificationResult,
};
#[cfg(feature = "verify")]
use crate::verify::VerifyResult;

/// 域名暴破结果
#[derive(Debug, Clone)]
pub struct SubdomainResult {
    pub domain: String,
    pub ip: String,
    pub query_type: crate::QueryType,
    pub record_type: String,
    pub timestamp: u64,
    #[cfg(feature = "verify")]
    pub verified: Option<VerifyResult>,
    #[cfg(feature = "dns-resolver")]
    pub dns_records: Option<DnsResolveResult>,
}

#[derive(Debug, Clone)]
pub struct SubdomainScanData {
    pub raw_results: Vec<SubdomainResult>,
    pub discovered_domains: Vec<DiscoveredDomain>,
    pub aggregated_domains: Vec<AggregatedDiscoveredDomain>,
    pub verification_results: Vec<VerificationResult>,
    pub summary: SummaryStats,
}

impl SubdomainResult {
    pub fn to_discovered_domain(&self) -> DiscoveredDomain {
        DiscoveredDomain {
            domain: self.domain.clone(),
            ip: self.ip.clone(),
            query_type: self.query_type,
            record_type: self.record_type.clone(),
            timestamp: self.timestamp,
        }
    }

    pub fn to_verification_result(&self) -> Option<VerificationResult> {
        #[cfg(feature = "verify")]
        {
            self.verified.as_ref().map(|verified| VerificationResult {
                domain: self.domain.clone(),
                ip: self.ip.clone(),
                http_status: verified.http_status,
                https_status: verified.https_status,
                title: verified.title.clone(),
                server: verified.server_header.clone(),
                is_alive: verified.http_alive || verified.https_alive,
            })
        }

        #[cfg(not(feature = "verify"))]
        {
            None
        }
    }
}

impl SubdomainScanData {
    pub fn from_results(results: &[SubdomainResult]) -> Self {
        let discovered_domains = results
            .iter()
            .map(SubdomainResult::to_discovered_domain)
            .collect::<Vec<_>>();
        let aggregated_domains = aggregate_discovered_domains(&discovered_domains);
        let verification_results = results
            .iter()
            .filter_map(SubdomainResult::to_verification_result)
            .collect::<Vec<_>>();
        let summary = generate_summary_from_data(&discovered_domains, &verification_results);

        SubdomainScanData {
            raw_results: results.to_vec(),
            discovered_domains,
            aggregated_domains,
            verification_results,
            summary,
        }
    }
}

fn aggregate_discovered_domains(
    discovered_domains: &[DiscoveredDomain],
) -> Vec<AggregatedDiscoveredDomain> {
    let mut aggregated: Vec<AggregatedDiscoveredDomain> = Vec::new();

    for discovered in discovered_domains {
        if let Some(existing) = aggregated
            .iter_mut()
            .find(|entry| entry.domain == discovered.domain)
        {
            existing.raw_record_count += 1;
            existing.first_seen = existing.first_seen.min(discovered.timestamp);
            existing.last_seen = existing.last_seen.max(discovered.timestamp);
            upsert_record_value(
                &mut existing.records,
                &discovered.record_type,
                &discovered.ip,
            );
            continue;
        }

        aggregated.push(AggregatedDiscoveredDomain {
            domain: discovered.domain.clone(),
            records: vec![AggregatedRecordValues {
                record_type: discovered.record_type.clone(),
                values: vec![discovered.ip.clone()],
            }],
            raw_record_count: 1,
            first_seen: discovered.timestamp,
            last_seen: discovered.timestamp,
        });
    }

    aggregated.sort_by(|left, right| left.domain.cmp(&right.domain));
    aggregated
}

fn upsert_record_value(records: &mut Vec<AggregatedRecordValues>, record_type: &str, value: &str) {
    if let Some(existing) = records
        .iter_mut()
        .find(|record| record.record_type == record_type)
    {
        if !existing
            .values
            .iter()
            .any(|existing_value| existing_value == value)
        {
            existing.values.push(value.to_string());
        }
        return;
    }

    records.push(AggregatedRecordValues {
        record_type: record_type.to_string(),
        values: vec![value.to_string()],
    });
}

#[cfg(test)]
mod tests {
    use super::{SubdomainResult, SubdomainScanData};

    #[test]
    fn scan_data_is_derived_from_results() {
        let results = vec![SubdomainResult {
            domain: "www.example.com".to_string(),
            ip: "1.1.1.1".to_string(),
            query_type: crate::QueryType::A,
            record_type: "A".to_string(),
            timestamp: 1,
            #[cfg(feature = "verify")]
            verified: None,
            #[cfg(feature = "dns-resolver")]
            dns_records: None,
        }];

        let scan_data = SubdomainScanData::from_results(&results);

        assert_eq!(scan_data.discovered_domains.len(), 1);
        assert_eq!(scan_data.raw_results.len(), 1);
        assert_eq!(scan_data.aggregated_domains.len(), 1);
        assert_eq!(scan_data.summary.total_domains, 1);
        assert_eq!(scan_data.summary.unique_domains, 1);
        assert!(scan_data.summary.unique_ips.contains("1.1.1.1"));
        assert!(scan_data.verification_results.is_empty());
    }

    #[test]
    fn scan_data_aggregates_records_by_domain() {
        let results = vec![
            SubdomainResult {
                domain: "www.example.com".to_string(),
                ip: "alias.example.net".to_string(),
                query_type: crate::QueryType::Cname,
                record_type: "CNAME".to_string(),
                timestamp: 1,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            },
            SubdomainResult {
                domain: "www.example.com".to_string(),
                ip: "1.1.1.1".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 2,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            },
            SubdomainResult {
                domain: "www.example.com".to_string(),
                ip: "1.1.1.2".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 3,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            },
        ];

        let scan_data = SubdomainScanData::from_results(&results);
        let aggregated = &scan_data.aggregated_domains[0];

        assert_eq!(aggregated.domain, "www.example.com");
        assert_eq!(aggregated.raw_record_count, 3);
        assert_eq!(aggregated.records.len(), 2);
        assert_eq!(aggregated.records[0].record_type, "CNAME");
        assert_eq!(aggregated.records[1].record_type, "A");
        assert_eq!(aggregated.records[1].values, vec!["1.1.1.1", "1.1.1.2"]);
        assert_eq!(scan_data.summary.total_domains, 3);
        assert_eq!(scan_data.summary.unique_domains, 1);
    }
}
