use std::collections::HashMap;

use crate::asset::analyze_cdn_metadata;
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
    pub value: String,
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

#[derive(Debug, Clone, Copy)]
pub struct CdnAnalysisOptions {
    pub detect: bool,
    pub collapse: bool,
}

impl Default for CdnAnalysisOptions {
    fn default() -> Self {
        Self {
            detect: true,
            collapse: true,
        }
    }
}

impl SubdomainResult {
    pub fn to_discovered_domain(&self) -> DiscoveredDomain {
        DiscoveredDomain {
            domain: self.domain.clone(),
            value: self.value.clone(),
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
                ip: self.value.clone(),
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
        Self::from_results_with_options(results, CdnAnalysisOptions::default())
    }

    pub fn from_results_with_options(
        results: &[SubdomainResult],
        cdn_options: CdnAnalysisOptions,
    ) -> Self {
        let discovered_domains = results
            .iter()
            .map(SubdomainResult::to_discovered_domain)
            .collect::<Vec<_>>();
        let aggregated_domains = aggregate_discovered_domains(results, cdn_options);
        let verification_results = results
            .iter()
            .filter_map(SubdomainResult::to_verification_result)
            .collect::<Vec<_>>();
        let summary = generate_summary_from_data(
            &discovered_domains,
            &aggregated_domains,
            &verification_results,
        );

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
    results: &[SubdomainResult],
    cdn_options: CdnAnalysisOptions,
) -> Vec<AggregatedDiscoveredDomain> {
    let mut aggregated: Vec<AggregatedDiscoveredDomain> = Vec::new();
    #[cfg(feature = "dns-resolver")]
    let mut dns_records_by_domain = HashMap::new();

    for result in results {
        #[cfg(feature = "dns-resolver")]
        if let Some(dns_records) = result.dns_records.clone() {
            dns_records_by_domain
                .entry(result.domain.clone())
                .or_insert(dns_records);
        }

        let discovered = result.to_discovered_domain();
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
                &discovered.value,
            );
            continue;
        }

        aggregated.push(AggregatedDiscoveredDomain {
            domain: discovered.domain.clone(),
            records: vec![AggregatedRecordValues {
                record_type: discovered.record_type.clone(),
                values: vec![discovered.value.clone()],
            }],
            has_cdn: false,
            possible_cdn: false,
            cdn_provider: None,
            cdn_confidence: None,
            cdn_evidence: Vec::new(),
            cdn_signals: Vec::new(),
            raw_record_count: 1,
            first_seen: discovered.timestamp,
            last_seen: discovered.timestamp,
        });
    }

    #[cfg(feature = "dns-resolver")]
    for entry in &mut aggregated {
        let dns_records = dns_records_by_domain.get(&entry.domain);
        apply_cdn_enrichment(entry, dns_records, cdn_options);
        apply_possible_cdn_signals(entry);
    }

    #[cfg(not(feature = "dns-resolver"))]
    for entry in &mut aggregated {
        apply_cdn_enrichment(entry, cdn_options);
        apply_possible_cdn_signals(entry);
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

#[cfg(feature = "dns-resolver")]
fn apply_cdn_enrichment(
    entry: &mut AggregatedDiscoveredDomain,
    dns_records: Option<&DnsResolveResult>,
    cdn_options: CdnAnalysisOptions,
) {
    if !cdn_options.detect {
        return;
    }

    if let Some(metadata) = analyze_cdn_metadata(entry, dns_records) {
        entry.has_cdn = true;
        entry.cdn_provider = Some(metadata.provider);
        entry.cdn_confidence = Some(metadata.confidence);
        entry.cdn_evidence = metadata.evidence;
        if cdn_options.collapse {
            collapse_cdn_ip_records(entry);
        }
    }
}

#[cfg(not(feature = "dns-resolver"))]
fn apply_cdn_enrichment(entry: &mut AggregatedDiscoveredDomain, cdn_options: CdnAnalysisOptions) {
    if !cdn_options.detect {
        return;
    }

    if let Some(metadata) = analyze_cdn_metadata(entry) {
        entry.has_cdn = true;
        entry.cdn_provider = Some(metadata.provider);
        entry.cdn_confidence = Some(metadata.confidence);
        entry.cdn_evidence = metadata.evidence;
        if cdn_options.collapse {
            collapse_cdn_ip_records(entry);
        }
    }
}

fn collapse_cdn_ip_records(entry: &mut AggregatedDiscoveredDomain) {
    for record in &mut entry.records {
        if !matches!(record.record_type.as_str(), "A" | "AAAA") || record.values.len() <= 1 {
            continue;
        }

        record.values.sort();
        record.values.dedup();
        record.values.truncate(1);
    }
}

fn apply_possible_cdn_signals(entry: &mut AggregatedDiscoveredDomain) {
    if entry.has_cdn {
        entry.possible_cdn = false;
        entry.cdn_signals.clear();
        return;
    }

    let mut signals = Vec::new();

    for record in &entry.records {
        if !matches!(record.record_type.as_str(), "A" | "AAAA") || record.values.len() <= 1 {
            continue;
        }

        signals.push(crate::handle::CdnEvidence {
            source: format!("MULTI_{}", record.record_type),
            value: entry.domain.clone(),
            detail: format!(
                "{} {} values on one hostname; weak CDN/load-balancing signal",
                record.values.len(),
                record.record_type
            ),
        });
    }

    entry.possible_cdn = !signals.is_empty();
    entry.cdn_signals = signals;
}

#[cfg(test)]
mod tests {
    use super::{CdnAnalysisOptions, SubdomainResult, SubdomainScanData};
    #[cfg(feature = "dns-resolver")]
    use crate::dns_resolver::{DnsRecord, DnsResolveResult};
    #[cfg(feature = "dns-resolver")]
    use std::collections::HashMap;

    #[test]
    fn scan_data_is_derived_from_results() {
        let results = vec![SubdomainResult {
            domain: "www.example.com".to_string(),
            value: "1.1.1.1".to_string(),
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
                value: "alias.example.net".to_string(),
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
                value: "1.1.1.1".to_string(),
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
                value: "1.1.1.2".to_string(),
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

    #[cfg(feature = "dns-resolver")]
    #[test]
    fn scan_data_collapses_cdn_a_values_and_marks_provider() {
        let mut dns_record_map = HashMap::new();
        dns_record_map.insert(
            "PTR".to_string(),
            vec![DnsRecord::PTR("edge-1.example.cloudflare.net".to_string())],
        );

        let dns_records = DnsResolveResult {
            domain: "cdn.example.com".to_string(),
            records: dns_record_map,
            has_records: true,
        };

        let results = vec![
            SubdomainResult {
                domain: "cdn.example.com".to_string(),
                value: "104.16.0.1".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 1,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: Some(dns_records.clone()),
            },
            SubdomainResult {
                domain: "cdn.example.com".to_string(),
                value: "104.16.0.2".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 2,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: Some(dns_records),
            },
        ];

        let scan_data = SubdomainScanData::from_results(&results);
        let aggregated = &scan_data.aggregated_domains[0];

        assert!(aggregated.has_cdn);
        assert!(!aggregated.possible_cdn);
        assert_eq!(aggregated.cdn_provider.as_deref(), Some("Cloudflare"));
        assert_eq!(
            aggregated
                .cdn_confidence
                .as_ref()
                .map(|value| value.as_str()),
            Some("high")
        );
        assert_eq!(aggregated.records.len(), 1);
        assert_eq!(aggregated.records[0].record_type, "A");
        assert_eq!(aggregated.records[0].values.len(), 1);
        assert_eq!(aggregated.raw_record_count, 2);
        assert!(!aggregated.cdn_evidence.is_empty());
        assert!(aggregated.cdn_signals.is_empty());
    }

    #[cfg(feature = "dns-resolver")]
    #[test]
    fn scan_data_keeps_all_cdn_a_values_when_collapse_is_disabled() {
        let mut dns_record_map = HashMap::new();
        dns_record_map.insert(
            "PTR".to_string(),
            vec![DnsRecord::PTR("edge-1.example.cloudflare.net".to_string())],
        );

        let dns_records = DnsResolveResult {
            domain: "cdn.example.com".to_string(),
            records: dns_record_map,
            has_records: true,
        };

        let results = vec![
            SubdomainResult {
                domain: "cdn.example.com".to_string(),
                value: "104.16.0.1".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 1,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: Some(dns_records.clone()),
            },
            SubdomainResult {
                domain: "cdn.example.com".to_string(),
                value: "104.16.0.2".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 2,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: Some(dns_records),
            },
        ];

        let scan_data = SubdomainScanData::from_results_with_options(
            &results,
            CdnAnalysisOptions {
                detect: true,
                collapse: false,
            },
        );
        let aggregated = &scan_data.aggregated_domains[0];

        assert!(aggregated.has_cdn);
        assert!(!aggregated.possible_cdn);
        assert_eq!(aggregated.records[0].record_type, "A");
        assert_eq!(aggregated.records[0].values.len(), 2);
    }

    #[cfg(feature = "dns-resolver")]
    #[test]
    fn scan_data_skips_cdn_enrichment_when_detection_is_disabled() {
        let mut dns_record_map = HashMap::new();
        dns_record_map.insert(
            "PTR".to_string(),
            vec![DnsRecord::PTR("edge-1.example.cloudflare.net".to_string())],
        );

        let dns_records = DnsResolveResult {
            domain: "cdn.example.com".to_string(),
            records: dns_record_map,
            has_records: true,
        };

        let results = vec![SubdomainResult {
            domain: "cdn.example.com".to_string(),
            value: "104.16.0.1".to_string(),
            query_type: crate::QueryType::A,
            record_type: "A".to_string(),
            timestamp: 1,
            #[cfg(feature = "verify")]
            verified: None,
            #[cfg(feature = "dns-resolver")]
            dns_records: Some(dns_records),
        }];

        let scan_data = SubdomainScanData::from_results_with_options(
            &results,
            CdnAnalysisOptions {
                detect: false,
                collapse: true,
            },
        );
        let aggregated = &scan_data.aggregated_domains[0];

        assert!(!aggregated.has_cdn);
        assert!(!aggregated.possible_cdn);
        assert!(aggregated.cdn_provider.is_none());
        assert!(aggregated.cdn_confidence.is_none());
        assert!(aggregated.cdn_evidence.is_empty());
    }

    #[test]
    fn scan_data_marks_multi_a_as_possible_cdn_only() {
        let results = vec![
            SubdomainResult {
                domain: "edge.example.com".to_string(),
                value: "1.1.1.1".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 1,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            },
            SubdomainResult {
                domain: "edge.example.com".to_string(),
                value: "1.1.1.2".to_string(),
                query_type: crate::QueryType::A,
                record_type: "A".to_string(),
                timestamp: 2,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            },
        ];

        let scan_data = SubdomainScanData::from_results(&results);
        let aggregated = &scan_data.aggregated_domains[0];

        assert!(!aggregated.has_cdn);
        assert!(aggregated.possible_cdn);
        assert!(aggregated.cdn_provider.is_none());
        assert!(aggregated.cdn_confidence.is_none());
        assert!(aggregated.cdn_evidence.is_empty());
        assert_eq!(aggregated.cdn_signals.len(), 1);
        assert_eq!(aggregated.cdn_signals[0].source, "MULTI_A");
        assert_eq!(aggregated.records[0].values.len(), 2);
    }
}
