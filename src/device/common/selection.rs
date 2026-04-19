use pnet::datalink;

use crate::device::resolve_route_to_target;
use crate::model::{EthTable, PacketTransport};

use super::choose_probe_target;
use super::probing::{
    default_probe_target, first_ipv4_on_interface, resolve_best_device,
    resolve_next_hop_mac_on_interface,
};

/// 根据设备名称获取设备信息
pub fn get_device_by_name(device_name: &str) -> Result<EthTable, String> {
    get_device_by_name_for_dns(device_name, &[])
}

/// 根据设备名称和DNS服务器获取设备信息
pub fn get_device_by_name_for_dns(
    device_name: &str,
    dns_servers: &[String],
) -> Result<EthTable, String> {
    let probe_target = choose_probe_target(dns_servers)
        .ok_or_else(|| "未找到可用于原始发包的DNS探测目标".to_string())?;
    let route = resolve_route_to_target(probe_target)?;
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == device_name && !iface.is_loopback())
        .ok_or_else(|| format!("未找到指定网络接口 {}", device_name))?;
    let src_ip = first_ipv4_on_interface(&interface)
        .ok_or_else(|| format!("接口 {} 没有可用的IPv4地址", interface.name))?;

    if let Some(route_interface) = route.interface.as_ref() {
        if route_interface != &interface.name {
            return Err(format!(
                "指定接口 {} 与系统路由接口 {} 不一致，拒绝使用错误网卡",
                interface.name, route_interface
            ));
        }
    }

    if let Some(src_mac) = interface.mac {
        let next_hop_ip = route.gateway.unwrap_or(probe_target);
        let dst_mac =
            resolve_next_hop_mac_on_interface(src_ip, probe_target, next_hop_ip, &interface.name)?;

        return Ok(EthTable {
            src_ip,
            device: interface.name,
            src_mac,
            dst_mac,
            transport: PacketTransport::Ethernet,
        });
    }

    Ok(EthTable {
        src_ip,
        device: interface.name,
        src_mac: pnet::util::MacAddr::zero(),
        dst_mac: pnet::util::MacAddr::zero(),
        transport: PacketTransport::Udp,
    })
}

/// 自动检测并选择最佳网络设备
pub async fn auto_get_devices() -> Result<EthTable, String> {
    auto_get_devices_for_dns(&[]).await
}

/// 根据DNS服务器自动检测网络设备
pub async fn auto_get_devices_for_dns(dns_servers: &[String]) -> Result<EthTable, String> {
    let probe_target = choose_probe_target(dns_servers).unwrap_or_else(default_probe_target);
    resolve_best_device(probe_target)
}
