use std::net::Ipv4Addr;

mod common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub use common::{
    auto_get_devices, auto_get_devices_for_dns, get_device_by_name, get_device_by_name_for_dns,
    list_network_devices, print_network_devices, NetworkDevice,
};

pub(super) fn resolve_route_to_target(
    probe_target: Ipv4Addr,
) -> Result<common::RouteResolution, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::resolve_route_to_target(probe_target);
    }

    #[cfg(target_os = "linux")]
    {
        return linux::resolve_route_to_target(probe_target);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = probe_target;
        Err("当前平台尚未实现路由探测，请手动指定网络设备".to_string())
    }
}

pub(super) fn lookup_arp_cache(
    target_ip: Ipv4Addr,
    interface_name: &str,
) -> Option<pnet::util::MacAddr> {
    #[cfg(target_os = "macos")]
    {
        return macos::lookup_arp_cache(target_ip, interface_name);
    }

    #[cfg(target_os = "linux")]
    {
        return linux::lookup_arp_cache(target_ip, interface_name);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (target_ip, interface_name);
        None
    }
}
