use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

use super::common::{is_valid_next_hop_mac, parse_mac_addr, RouteResolution};

pub(super) fn resolve_route_to_target(probe_target: Ipv4Addr) -> Result<RouteResolution, String> {
    let output = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg(probe_target.to_string())
        .output()
        .map_err(|error| format!("执行 route -n get 失败: {}", error))?;

    if !output.status.success() {
        return Err(format!(
            "route -n get 返回失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interface = parse_route_field(&stdout, "interface");
    let gateway = parse_route_field(&stdout, "gateway")
        .and_then(|value| parse_gateway_field(&value, probe_target));

    Ok(RouteResolution { interface, gateway })
}

pub(super) fn lookup_arp_cache(
    target_ip: Ipv4Addr,
    interface_name: &str,
) -> Option<pnet::util::MacAddr> {
    let output = Command::new("arp")
        .arg("-n")
        .arg(target_ip.to_string())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_arp_cache_output(&stdout, interface_name)
}

fn parse_route_field(output: &str, key: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let prefix = format!("{}:", key);
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn parse_gateway_field(value: &str, probe_target: Ipv4Addr) -> Option<Ipv4Addr> {
    if value.starts_with("link#") {
        return Some(probe_target);
    }

    Ipv4Addr::from_str(value).ok()
}

fn parse_arp_cache_output(output: &str, interface_name: &str) -> Option<pnet::util::MacAddr> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("no entry") || trimmed.contains("incomplete") {
            continue;
        }

        if !trimmed.contains(&format!(" on {}", interface_name)) {
            continue;
        }

        let marker = " at ";
        let start = trimmed.find(marker)?;
        let rest = &trimmed[start + marker.len()..];
        let mac_text = rest.split_whitespace().next()?;
        if mac_text == "(incomplete)" {
            continue;
        }

        if let Some(mac) = parse_mac_addr(mac_text) {
            if !is_valid_next_hop_mac(mac) {
                continue;
            }

            return Some(mac);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::parse_arp_cache_output;

    #[test]
    fn parse_arp_cache_output_accepts_zero_oui_unicast_mac() {
        let output = "? (10.213.192.1) at 0:0:0:0:0:1 on en0 ifscope [ethernet]";

        assert_eq!(
            parse_arp_cache_output(output, "en0").unwrap().to_string(),
            "00:00:00:00:00:01"
        );
    }

    #[test]
    fn parse_arp_cache_output_accepts_valid_unicast_mac() {
        let output = "? (10.213.192.1) at ac:de:48:00:11:22 on en0 ifscope [ethernet]";

        assert_eq!(
            parse_arp_cache_output(output, "en0").unwrap().to_string(),
            "ac:de:48:00:11:22"
        );
    }
}
