use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

use super::common::{parse_mac_addr, RouteResolution};

pub(super) fn resolve_route_to_target(probe_target: Ipv4Addr) -> Result<RouteResolution, String> {
    let output = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg(probe_target.to_string())
        .output()
        .map_err(|error| format!("执行 ip route get 失败: {}", error))?;

    if !output.status.success() {
        return Err(format!(
            "ip route get 返回失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let tokens: Vec<&str> = stdout.split_whitespace().collect();
    let interface = token_after(&tokens, "dev").map(|value| value.to_string());
    let gateway = token_after(&tokens, "via").and_then(|value| Ipv4Addr::from_str(value).ok());

    Ok(RouteResolution { interface, gateway })
}

pub(super) fn lookup_arp_cache(
    target_ip: Ipv4Addr,
    interface_name: &str,
) -> Option<pnet::util::MacAddr> {
    let output = Command::new("ip")
        .arg("neigh")
        .arg("show")
        .arg(target_ip.to_string())
        .arg("dev")
        .arg(interface_name)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ip_neigh_output(&stdout)
}

fn parse_ip_neigh_output(output: &str) -> Option<pnet::util::MacAddr> {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mac_text = token_after(&tokens, "lladdr")?;
        if mac_text == "FAILED" {
            continue;
        }
        if let Some(mac) = parse_mac_addr(mac_text) {
            return Some(mac);
        }
    }

    None
}

fn token_after<'a>(tokens: &'a [&'a str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1).copied())
}
