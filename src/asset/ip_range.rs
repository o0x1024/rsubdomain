use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

static CDN_IP_RANGES_TEXT: &str = include_str!("../../data/cdn_ip_ranges.txt");
static CDN_IP_RANGES: OnceLock<Vec<IpRangeRule>> = OnceLock::new();
static CDN_IP_RANGE_CACHE: OnceLock<Mutex<HashMap<IpAddr, Option<IpRangeMatch>>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpRangeMatch {
    pub provider: String,
    pub cidr: String,
}

#[derive(Debug, PartialEq, Eq)]
struct IpRangeRule {
    provider: String,
    network: IpNetwork,
    cidr: String,
}

#[derive(Debug, PartialEq, Eq)]
enum IpNetwork {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

pub(crate) fn match_ip_to_cdn_provider(ip: IpAddr) -> Option<IpRangeMatch> {
    let cache = CDN_IP_RANGE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock() {
        if let Some(cached) = cache.get(&ip) {
            return cached.clone();
        }
    }

    let matched = ip_range_rules()
        .iter()
        .find(|rule| rule.network.contains(ip))
        .map(|rule| IpRangeMatch {
            provider: rule.provider.clone(),
            cidr: rule.cidr.clone(),
        });

    if let Ok(mut cache) = cache.lock() {
        cache.insert(ip, matched.clone());
    }

    matched
}

fn ip_range_rules() -> &'static [IpRangeRule] {
    CDN_IP_RANGES.get_or_init(|| parse_ip_range_rules(CDN_IP_RANGES_TEXT))
}

fn parse_ip_range_rules(content: &str) -> Vec<IpRangeRule> {
    content.lines().filter_map(parse_ip_range_line).collect()
}

fn parse_ip_range_line(line: &str) -> Option<IpRangeRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let (provider, cidr) = trimmed.split_once(',')?;
    let provider = provider.trim();
    let cidr = cidr.trim();
    let network = IpNetwork::from_cidr(cidr)?;

    Some(IpRangeRule {
        provider: provider.to_string(),
        network,
        cidr: cidr.to_string(),
    })
}

impl IpNetwork {
    fn from_cidr(cidr: &str) -> Option<Self> {
        let (ip_part, prefix_part) = cidr.split_once('/')?;
        let prefix = prefix_part.trim().parse::<u8>().ok()?;
        let ip = IpAddr::from_str(ip_part.trim()).ok()?;

        match ip {
            IpAddr::V4(ipv4) if prefix <= 32 => Some(IpNetwork::V4(ipv4, prefix)),
            IpAddr::V6(ipv6) if prefix <= 128 => Some(IpNetwork::V6(ipv6, prefix)),
            _ => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpNetwork::V4(network, prefix), IpAddr::V4(ipv4)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(*prefix))
                };
                (u32::from(*network) & mask) == (u32::from(ipv4) & mask)
            }
            (IpNetwork::V6(network, prefix), IpAddr::V6(ipv6)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u128::from(*prefix))
                };
                ipv6_to_u128(*network) & mask == ipv6_to_u128(ipv6) & mask
            }
            _ => false,
        }
    }
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        match_ip_to_cdn_provider, parse_ip_range_line, parse_ip_range_rules, IpNetwork,
        CDN_IP_RANGES_TEXT,
    };

    #[test]
    fn parses_ipv4_cidr_rule() {
        let rule = parse_ip_range_line("Cloudflare,104.16.0.0/13").unwrap();
        assert_eq!(rule.provider, "Cloudflare");
        assert_eq!(rule.cidr, "104.16.0.0/13");
    }

    #[test]
    fn ipv4_network_contains_expected_address() {
        let network = IpNetwork::from_cidr("104.16.0.0/13").unwrap();
        assert!(network.contains(IpAddr::V4(Ipv4Addr::new(104, 20, 1, 1))));
        assert!(!network.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn matches_cloudflare_ip_range() {
        let matched = match_ip_to_cdn_provider(IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)));
        assert_eq!(
            matched.as_ref().map(|value| value.provider.as_str()),
            Some("Cloudflare")
        );
    }

    #[test]
    fn embedded_ip_ranges_have_no_duplicate_cidrs() {
        let rules = parse_ip_range_rules(CDN_IP_RANGES_TEXT);
        let mut seen = HashSet::new();

        for rule in rules {
            assert!(seen.insert((rule.provider, rule.cidr)));
        }
    }
}
