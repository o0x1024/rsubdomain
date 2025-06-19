use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::{
    datalink,
    packet::{
        dns::DnsPacket, ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet,
        udp::UdpPacket, Packet,
    },
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter::repeat_with;
use std::sync::mpsc;
use std::{
    net::IpAddr,
    process::Command,
    sync::mpsc::{Receiver, Sender},
    
};

use crate::model::EthTable;
use pnet::datalink::Channel::Ethernet;

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
    let interfaces = datalink::interfaces();
    let mut devices = Vec::new();
    
    for interface in interfaces {
        let device = NetworkDevice {
            name: interface.name.clone(),
            description: Some(interface.description.clone()),
            mac: interface.mac,
            ips: interface.ips.iter().map(|ip| ip.ip()).collect(),
            is_up: interface.is_up(),
            is_loopback: interface.is_loopback(),
        };
        devices.push(device);
    }
    
    devices
}

/// 打印网络设备列表
pub fn print_network_devices() {
    let devices = list_network_devices();
    
    println!("\n{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}", 
        "设备名称", "MAC地址", "IP地址", "状态", "类型", "描述");
    println!("{}", "-".repeat(100));
    
    for device in devices {
        let mac_str = device.mac.map_or("N/A".to_string(), |mac| mac.to_string());
        let status = if device.is_up { "UP" } else { "DOWN" };
        let device_type = if device.is_loopback { "LOOPBACK" } else { "ETHERNET" };
        let description = device.description.as_deref().unwrap_or("N/A");
        
        if device.ips.is_empty() {
            println!("{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}", 
                device.name, mac_str, "N/A", status, device_type, description);
        } else {
            for (i, ip) in device.ips.iter().enumerate() {
                if i == 0 {
                    println!("{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}", 
                        device.name, mac_str, ip.to_string(), status, device_type, description);
                } else {
                    println!("{:<20} {:<18} {:<15} {:<8} {:<10} {:<30}", 
                        "", "", ip.to_string(), "", "", "");
                }
            }
        }
    }
}

/// 根据设备名称获取设备信息
pub fn get_device_by_name(device_name: &str) -> Option<EthTable> {
    let interfaces = datalink::interfaces();
    
    for interface in interfaces {
        if interface.name == device_name && !interface.is_loopback() {
            // 查找IPv4地址
            for ip_network in interface.ips {
                if let IpAddr::V4(ipv4) = ip_network.ip() {
                    // 尝试获取网关MAC地址
                    if let Some(gateway_mac) = get_gateway_mac(&interface.name) {
                        return Some(EthTable {
                            src_ip: ipv4,
                            device: interface.name,
                            src_mac: interface.mac.unwrap_or_default(),
                            dst_mac: gateway_mac,
                        });
                    } else {
                        // 如果无法获取网关MAC，使用默认值
                        return Some(EthTable {
                            src_ip: ipv4,
                            device: interface.name,
                            src_mac: interface.mac.unwrap_or_default(),
                            dst_mac: pnet::util::MacAddr::zero(),
                        });
                    }
                }
            }
        }
    }
    
    None
}

/// 尝试获取网关MAC地址（简化实现）
fn get_gateway_mac(interface_name: &str) -> Option<pnet::util::MacAddr> {
    // 这里可以实现ARP表查询或其他方法获取网关MAC
    // 暂时返回None，让自动检测流程处理
    None
}

/// 自动检测并选择最佳网络设备
pub fn auto_get_devices() -> EthTable {
    let interfaces = datalink::interfaces();

    // for iface in interfaces.clone(){
    //     println!("{:?}",iface);
    // }

    let (mptx, mprx): (Sender<EthTable>, Receiver<EthTable>) = mpsc::channel();
    let domain = random_str(4) + ".example.com";

    println!("test domain:{}", domain);
    for interface in interfaces {
        if !interface.is_loopback(){
            for ip in interface.ips.clone() {
                match ip.ip() {
                    IpAddr::V4(_) => {
                        let domain_clone = domain.clone();
                        let interface_clone = interface.clone();
                        let interface_name = interface.name.clone();
                        let mptx_clone = mptx.clone();
                        tokio::spawn(async move {
                            let (_, mut rx) =
                                match datalink::channel(&interface_clone, Default::default()) {
                                    Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
                                    Ok(_) => panic!("Unhandled channel type"),
                                    Err(e) => panic!(
                                        "An error occurred when creating the datalink channel: {}",
                                        e
                                    ),
                                };
                            loop {
                                match rx.next() {
                                    Ok(packet) => {
                                        let ethernet = EthernetPacket::new(packet).unwrap();
                                        match ethernet.get_ethertype() {
                                            EtherTypes::Ipv4 => {
                                                let ipv4_packet =
                                                    Ipv4Packet::new(ethernet.payload()).unwrap();
                                                match ipv4_packet.get_next_level_protocol() {
                                                    IpNextHeaderProtocols::Udp => {
                                                        let udp_packet =
                                                            UdpPacket::new(ipv4_packet.payload())
                                                                .unwrap();

                                                        if udp_packet.get_source() != 53 {
                                                            continue;
                                                        }

                                                        if let Some(dns) =
                                                            DnsPacket::new(udp_packet.payload())
                                                        {
                                                            for query in dns.get_queries() {
                                                                let recv_domain =
                                                                    query.get_qname_parsed();
                                                                if recv_domain
                                                                    .contains(&domain_clone)
                                                                {
                                                                    let ipv4 = match ip.ip() {
                                                                            IpAddr::V4(addr) => addr,
                                                                            IpAddr::V6(_) => panic!("Expected an IPv4 address, got an IPv6 address"),
                                                                        };
                                                                    if let Err(err) = mptx_clone
                                                                        .send(EthTable {
                                                                            src_ip: ipv4,
                                                                            device: interface_name,
                                                                            src_mac: ethernet
                                                                                .get_destination(),
                                                                            dst_mac: ethernet
                                                                                .get_source(),
                                                                        })
                                                                    {
                                                                        println!("An error occurred when sending the message: {}", err);
                                                                    }
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    _ => (),
                                                }
                                            }
                                            EtherTypes::Ipv6 => {
                                                let ipv6_packet =
                                                    Ipv6Packet::new(ethernet.payload());
                                                if let Some(header) = ipv6_packet {
                                                    match header.get_next_header() {
                                                        IpNextHeaderProtocols::Udp => {
                                                            let udp_packet =
                                                                UdpPacket::new(header.payload())
                                                                    .unwrap();

                                                            if udp_packet.get_source() != 53 {
                                                                continue;
                                                            }

                                                            if let Some(dns) =
                                                                DnsPacket::new(udp_packet.payload())
                                                            {
                                                                for query in dns.get_queries() {
                                                                    let recv_domain =
                                                                        query.get_qname_parsed();
                                                                    if recv_domain
                                                                        .contains(&domain_clone)
                                                                    {
                                                                        println!("auto_get_device get domain:{}",recv_domain);
                                                                        let ipv4 = match ip.ip() {
                                                                        IpAddr::V4(addr) => addr,
                                                                        IpAddr::V6(_) => panic!("Expected an IPv4 address, got an IPv6 address"),
                                                                    };
                                                                        if let Err(err) = mptx_clone
                                                                        .send(EthTable {
                                                                            src_ip: ipv4,
                                                                            device: interface_name,
                                                                            src_mac: ethernet
                                                                                .get_destination(),
                                                                            dst_mac: ethernet
                                                                                .get_source(),
                                                                        })
                                                                    {
                                                                        println!("An error occurred when sending the message: {}", err);
                                                                    }
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        _ => (),
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    Err(e) => {
                                        println!(
                                            "An error occurred when reading from the datalink channel: {}",
                                            e
                                        );
                                        continue;
                                    }
                                }
                            }
                        });
                    }
                    _ => (),
                }
            }
        }
    }
    // thread::sleep(Duration::from_millis(3000));
    Command::new("nslookup")
        .arg(domain)
        .output()
        .expect("failed to execute process");

    match mprx.recv() {
        Ok(eth) => {
            // println!("eth: {:?}", eth);
            eth
        }
        Err(e) => {
            panic!("recv error:{}", e)
        }
    }
}

fn random_str(n: usize) -> String {
    let mut rng = thread_rng();
    // 生成一个长度为 n 的随机字符串
    repeat_with(|| rng.sample(Alphanumeric) as char)
        .take(n)
        .collect()
}
