use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::handle::{DiscoveredDomain, SummaryStats, VerificationResult};

/// 生成汇总统计
pub fn generate_summary_from_data(
    discovered: &[DiscoveredDomain],
    verified: &[VerificationResult],
) -> SummaryStats {
    let mut unique_ips = HashSet::new();
    let mut unique_domains = HashSet::new();
    let mut record_types = HashMap::new();
    let mut ip_ranges = HashMap::new();

    for domain in discovered {
        unique_domains.insert(domain.domain.clone());

        if let Ok(ip) = domain.ip.parse::<IpAddr>() {
            unique_ips.insert(domain.ip.clone());

            if let IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                let range = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                ip_ranges
                    .entry(range)
                    .or_insert_with(Vec::new)
                    .push(domain.ip.clone());
            }
        }

        *record_types.entry(domain.record_type.clone()).or_insert(0) += 1;
    }

    SummaryStats {
        total_domains: discovered.len(),
        unique_domains: unique_domains.len(),
        unique_ips,
        ip_ranges,
        record_types,
        verified_domains: verified.len(),
        alive_domains: verified.iter().filter(|result| result.is_alive).count(),
    }
}
