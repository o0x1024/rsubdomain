use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::handle::{
    AggregatedDiscoveredDomain, DiscoveredDomain, SummaryStats, VerificationResult,
};

/// 生成汇总统计
pub fn generate_summary_from_data(
    discovered: &[DiscoveredDomain],
    aggregated: &[AggregatedDiscoveredDomain],
    verified: &[VerificationResult],
) -> SummaryStats {
    let mut unique_ips = HashSet::new();
    let mut unique_domains = HashSet::new();
    let mut record_types = HashMap::new();
    let mut ip_ranges = HashMap::new();
    let mut cdn_providers = HashMap::new();
    let mut cdn_confidence = HashMap::new();
    let mut suspected_cdn_domains = 0;

    for domain in discovered {
        unique_domains.insert(domain.domain.clone());

        if let Ok(ip) = domain.value.parse::<IpAddr>() {
            unique_ips.insert(domain.value.clone());

            if let IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                let range = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                ip_ranges
                    .entry(range)
                    .or_insert_with(Vec::new)
                    .push(domain.value.clone());
            }
        }

        *record_types.entry(domain.record_type.clone()).or_insert(0) += 1;
    }

    let mut cdn_domains = 0;
    for domain in aggregated {
        if domain.possible_cdn {
            suspected_cdn_domains += 1;
        }

        if !domain.has_cdn {
            continue;
        }

        cdn_domains += 1;
        if let Some(provider) = &domain.cdn_provider {
            *cdn_providers.entry(provider.clone()).or_insert(0) += 1;
        }
        if let Some(confidence) = &domain.cdn_confidence {
            *cdn_confidence
                .entry(confidence.as_str().to_string())
                .or_insert(0) += 1;
        }
    }

    SummaryStats {
        total_domains: discovered.len(),
        unique_domains: unique_domains.len(),
        unique_ips,
        ip_ranges,
        record_types,
        cdn_domains,
        suspected_cdn_domains,
        cdn_providers,
        cdn_confidence,
        verified_domains: verified.len(),
        alive_domains: verified.iter().filter(|result| result.is_alive).count(),
    }
}
