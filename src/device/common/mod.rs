mod arp;
mod listing;
mod probing;
mod selection;

use std::net::Ipv4Addr;
use std::str::FromStr;

pub use listing::{list_network_devices, print_network_devices, NetworkDevice};
pub use selection::{
    auto_get_devices, auto_get_devices_for_dns, get_device_by_name, get_device_by_name_for_dns,
};

const DEFAULT_DNS_PROBE_TARGETS: &[&str] = &[
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "114.114.114.114",
    "8.8.8.8",
];

#[derive(Debug, Clone)]
pub(crate) struct RouteResolution {
    pub interface: Option<String>,
    pub gateway: Option<Ipv4Addr>,
}

pub(super) fn choose_probe_target(dns_servers: &[String]) -> Option<Ipv4Addr> {
    for server in dns_servers {
        if let Ok(ip) = Ipv4Addr::from_str(server.trim()) {
            return Some(ip);
        }
    }

    DEFAULT_DNS_PROBE_TARGETS
        .iter()
        .find_map(|value| Ipv4Addr::from_str(value).ok())
}

pub(super) fn parse_mac_addr(value: &str) -> Option<pnet::util::MacAddr> {
    let normalized = value.trim().replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut octets = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        octets[index] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(pnet::util::MacAddr::new(
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    ))
}

pub(super) fn is_valid_next_hop_mac(mac: pnet::util::MacAddr) -> bool {
    let octets = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];
    let is_zero = octets.iter().all(|octet| *octet == 0);
    let is_broadcast = octets.iter().all(|octet| *octet == u8::MAX);
    let is_multicast = (octets[0] & 0x01) == 0x01;

    !is_zero && !is_broadcast && !is_multicast
}
