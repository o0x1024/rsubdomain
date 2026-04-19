use log::info;
use pnet::datalink;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::Duration;

use crate::device::{lookup_arp_cache, resolve_route_to_target};
use crate::model::{EthTable, PacketTransport};

use super::choose_probe_target;

pub(super) fn default_probe_target() -> Ipv4Addr {
    choose_probe_target(&[]).unwrap_or(Ipv4Addr::new(223, 5, 5, 5))
}

pub(super) fn resolve_best_device(probe_target: Ipv4Addr) -> Result<EthTable, String> {
    let (interface_name, src_ip, src_mac) = detect_egress_interface(probe_target)?;
    let route = resolve_route_to_target(probe_target)?;

    if let Some(route_interface) = route.interface.as_ref() {
        if route_interface != &interface_name {
            return Err(format!(
                "系统路由接口 {} 与本地出接口 {} 不一致",
                route_interface, interface_name
            ));
        }
    }

    if let Some(src_mac) = src_mac {
        let next_hop_ip = route.gateway.unwrap_or(probe_target);
        let dst_mac = resolve_next_hop_mac(src_ip, probe_target, next_hop_ip, &interface_name)?;

        info!(
            "自动检测网络设备成功: interface={} transport=ethernet src_ip={} next_hop={} dst_mac={}",
            interface_name, src_ip, next_hop_ip, dst_mac
        );

        return Ok(EthTable {
            src_ip,
            device: interface_name,
            src_mac,
            dst_mac,
            transport: PacketTransport::Ethernet,
        });
    }

    info!(
        "自动检测网络设备成功: interface={} transport=udp src_ip={} (接口无MAC，切换为三层兼容模式)",
        interface_name, src_ip
    );

    Ok(EthTable {
        src_ip,
        device: interface_name,
        src_mac: pnet::util::MacAddr::zero(),
        dst_mac: pnet::util::MacAddr::zero(),
        transport: PacketTransport::Udp,
    })
}

pub(super) fn resolve_next_hop_mac_on_interface(
    src_ip: Ipv4Addr,
    probe_target: Ipv4Addr,
    next_hop_ip: Ipv4Addr,
    interface_name: &str,
) -> Result<pnet::util::MacAddr, String> {
    resolve_next_hop_mac(src_ip, probe_target, next_hop_ip, interface_name)
}

pub(super) fn first_ipv4_on_interface(interface: &datalink::NetworkInterface) -> Option<Ipv4Addr> {
    interface.ips.iter().find_map(|network| match network.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    })
}

fn detect_egress_interface(
    probe_target: Ipv4Addr,
) -> Result<(String, Ipv4Addr, Option<pnet::util::MacAddr>), String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("绑定UDP探测socket失败: {}", error))?;
    socket
        .connect(SocketAddrV4::new(probe_target, 53))
        .map_err(|error| format!("连接探测DNS服务器失败: {}", error))?;

    let local_ip = match socket
        .local_addr()
        .map_err(|error| format!("读取本地探测地址失败: {}", error))?
        .ip()
    {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => {
            return Err(format!("探测得到IPv6地址 {}，当前仅支持IPv4原始发包", ip));
        }
    };

    for interface in datalink::interfaces() {
        if interface.is_loopback() {
            continue;
        }

        let has_local_ip = interface
            .ips
            .iter()
            .any(|network| network.ip() == IpAddr::V4(local_ip));
        if !has_local_ip {
            continue;
        }

        return Ok((interface.name, local_ip, interface.mac));
    }

    Err(format!("未找到承载本地地址 {} 的有效网络接口", local_ip))
}

fn resolve_next_hop_mac(
    src_ip: Ipv4Addr,
    probe_target: Ipv4Addr,
    next_hop_ip: Ipv4Addr,
    interface_name: &str,
) -> Result<pnet::util::MacAddr, String> {
    if let Some(mac) = lookup_arp_cache(next_hop_ip, interface_name) {
        return Ok(mac);
    }

    for attempt in 0..5 {
        warm_up_neighbor_cache(src_ip, probe_target)
            .map_err(|error| format!("预热ARP缓存失败: {}", error))?;
        thread::sleep(Duration::from_millis(200 * (attempt + 1) as u64));

        if let Some(mac) = lookup_arp_cache(next_hop_ip, interface_name) {
            return Ok(mac);
        }
    }

    Err(format!(
        "无法解析下一跳 {} 在接口 {} 上的MAC地址",
        next_hop_ip, interface_name
    ))
}

fn warm_up_neighbor_cache(src_ip: Ipv4Addr, probe_target: Ipv4Addr) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind(SocketAddrV4::new(src_ip, 0))?;
    socket.set_write_timeout(Some(Duration::from_millis(500)))?;
    let _ = socket.send_to(&[0u8], SocketAddrV4::new(probe_target, 53));
    Ok(())
}
