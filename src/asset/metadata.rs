use std::collections::HashMap;
use std::net::IpAddr;

#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::{DnsRecord, DnsResolveResult};
use crate::handle::{AggregatedDiscoveredDomain, CdnConfidence, CdnEvidence};

use super::cdn::match_cdn_provider_by_candidate;
use super::ip_range::match_ip_to_cdn_provider;

#[derive(Debug, Clone)]
pub(crate) struct CdnMetadata {
    pub provider: String,
    pub confidence: CdnConfidence,
    pub evidence: Vec<CdnEvidence>,
}

#[derive(Debug, Clone)]
struct ProviderEvidence {
    provider: String,
    evidence: CdnEvidence,
}

pub(crate) fn analyze_cdn_metadata(
    entry: &AggregatedDiscoveredDomain,
    #[cfg(feature = "dns-resolver")] dns_records: Option<&DnsResolveResult>,
) -> Option<CdnMetadata> {
    let mut evidence = Vec::new();

    for (source, value) in collect_name_candidates(entry) {
        if let Some(matched) = match_cdn_provider_by_candidate(value.as_str()) {
            evidence.push(ProviderEvidence {
                provider: matched.provider,
                evidence: CdnEvidence {
                    source,
                    value,
                    detail: format!("{} match {}", matched.match_kind.as_str(), matched.pattern),
                },
            });
        }
    }

    #[cfg(feature = "dns-resolver")]
    if let Some(records) = dns_records {
        for (source, value) in collect_dns_name_candidates(records) {
            if let Some(matched) = match_cdn_provider_by_candidate(value.as_str()) {
                evidence.push(ProviderEvidence {
                    provider: matched.provider,
                    evidence: CdnEvidence {
                        source,
                        value,
                        detail: format!(
                            "{} match {}",
                            matched.match_kind.as_str(),
                            matched.pattern
                        ),
                    },
                });
            }
        }
    }

    for ip in collect_ip_candidates(entry) {
        if let Some(matched) = match_ip_to_cdn_provider(ip) {
            evidence.push(ProviderEvidence {
                provider: matched.provider,
                evidence: CdnEvidence {
                    source: "IP_RANGE".to_string(),
                    value: ip.to_string(),
                    detail: format!("matched {}", matched.cidr),
                },
            });
        }
    }

    if evidence.is_empty() {
        return None;
    }

    let provider = choose_provider(&evidence)?;
    let evidence = evidence
        .into_iter()
        .filter(|item| item.provider == provider)
        .map(|item| item.evidence)
        .collect::<Vec<_>>();
    let confidence = calculate_confidence(&evidence);

    Some(CdnMetadata {
        provider,
        confidence,
        evidence,
    })
}

fn choose_provider(evidence: &[ProviderEvidence]) -> Option<String> {
    let mut counts = HashMap::new();

    for item in evidence {
        *counts.entry(item.provider.clone()).or_insert(0usize) += confidence_weight(&item.evidence);
    }

    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)))
        .map(|(provider, _)| provider)
}

fn calculate_confidence(evidence: &[CdnEvidence]) -> CdnConfidence {
    let has_name_high_signal = evidence.iter().any(|item| {
        matches!(item.source.as_str(), "CNAME" | "NS") && item.detail.starts_with("suffix match")
    });
    let has_ptr = evidence.iter().any(|item| item.source == "PTR");
    let has_ip_range = evidence.iter().any(|item| item.source == "IP_RANGE");

    if has_name_high_signal || (has_ptr && has_ip_range) {
        return CdnConfidence::High;
    }

    if has_ptr || has_ip_range {
        return CdnConfidence::Medium;
    }

    CdnConfidence::Low
}

fn collect_name_candidates(entry: &AggregatedDiscoveredDomain) -> Vec<(String, String)> {
    entry
        .records
        .iter()
        .filter(|record| matches!(record.record_type.as_str(), "CNAME" | "NS"))
        .flat_map(|record| {
            record
                .values
                .iter()
                .cloned()
                .map(|value| (record.record_type.clone(), value))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(feature = "dns-resolver")]
fn collect_dns_name_candidates(records: &DnsResolveResult) -> Vec<(String, String)> {
    records
        .records
        .iter()
        .flat_map(|(record_type, values)| {
            values
                .iter()
                .filter_map(|record| match record {
                    DnsRecord::CNAME(value) | DnsRecord::NS(value) | DnsRecord::PTR(value) => {
                        Some((record_type.clone(), value.clone()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn collect_ip_candidates(entry: &AggregatedDiscoveredDomain) -> Vec<IpAddr> {
    entry
        .records
        .iter()
        .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
        .flat_map(|record| {
            record
                .values
                .iter()
                .filter_map(|value| value.parse::<IpAddr>().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn confidence_weight(evidence: &CdnEvidence) -> usize {
    match evidence.source.as_str() {
        "CNAME" | "NS" => 3,
        "PTR" => 2,
        "IP_RANGE" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use crate::handle::{AggregatedDiscoveredDomain, AggregatedRecordValues, CdnConfidence};

    use super::analyze_cdn_metadata;

    #[test]
    fn cname_suffix_match_is_high_confidence() {
        let entry = AggregatedDiscoveredDomain {
            domain: "cdn.example.com".to_string(),
            records: vec![AggregatedRecordValues {
                record_type: "CNAME".to_string(),
                values: vec!["foo.cloudflare.net".to_string()],
            }],
            has_cdn: false,
            possible_cdn: false,
            cdn_provider: None,
            cdn_confidence: None,
            cdn_evidence: Vec::new(),
            cdn_signals: Vec::new(),
            raw_record_count: 1,
            first_seen: 1,
            last_seen: 1,
        };

        let metadata = analyze_cdn_metadata(
            &entry,
            #[cfg(feature = "dns-resolver")]
            None,
        )
        .unwrap();
        assert_eq!(metadata.provider, "Cloudflare");
        assert_eq!(metadata.confidence, CdnConfidence::High);
    }
}
