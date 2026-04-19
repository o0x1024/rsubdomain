use pnet::datalink;

/// 网络设备信息
#[derive(Debug, Clone)]
pub struct NetworkDevice {
    pub name: String,
    pub description: Option<String>,
    pub mac: Option<pnet::util::MacAddr>,
    pub ips: Vec<std::net::IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// 列出所有可用的网络设备
pub fn list_network_devices() -> Vec<NetworkDevice> {
    datalink::interfaces()
        .into_iter()
        .map(|interface| NetworkDevice {
            name: interface.name.clone(),
            description: Some(interface.description.clone()),
            mac: interface.mac,
            ips: interface.ips.iter().map(|ip| ip.ip()).collect(),
            is_up: interface.is_up(),
            is_loopback: interface.is_loopback(),
        })
        .collect()
}

/// 打印网络设备列表
pub fn print_network_devices() {
    let devices = list_network_devices();

    println!(
        "\n{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}",
        "设备名称", "MAC地址", "IP地址", "状态", "类型", "描述"
    );
    println!("{}", "-".repeat(100));

    for device in devices {
        let mac_str = device.mac.map_or("N/A".to_string(), |mac| mac.to_string());
        let status = if device.is_up { "UP" } else { "DOWN" };
        let device_type = if device.is_loopback {
            "LOOPBACK"
        } else {
            "ETHERNET"
        };
        let description = device.description.as_deref().unwrap_or("N/A");

        if device.ips.is_empty() {
            println!(
                "{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}",
                device.name, mac_str, "N/A", status, device_type, description
            );
            continue;
        }

        for (index, ip) in device.ips.iter().enumerate() {
            if index == 0 {
                println!(
                    "{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}",
                    device.name,
                    mac_str,
                    ip.to_string(),
                    status,
                    device_type,
                    description
                );
            } else {
                println!(
                    "{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}",
                    "",
                    "",
                    ip.to_string(),
                    "",
                    "",
                    ""
                );
            }
        }
    }
}
