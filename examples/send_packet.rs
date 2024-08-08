use pnet::datalink;
use pnet::packet::dns::{MutableDnsPacket,DnsPacket, MutableDnsQueryPacket};
use pnet::packet::ethernet::{self, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::IcmpCodes;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::ipv4::Ipv4Flags::DontFragment;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::{ip::IpNextHeaderProtocols, util, Packet};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use pnet::datalink::Channel::Ethernet;

fn main() {
    // 获取网络接口
    let flg = 2;

    if flg == 1 {
        send_by_tranport();
    } else if flg == 2 {
        send_by_datalink();
    } else {
        send_icmp_datalink();
    }

    // println!("DNS query sent!");
}
const ICMP_SIZE: usize = 40;
fn send_icmp_datalink() {
    let interfaces = datalink::interfaces();

    for interface in interfaces.iter() {
        if interface.name == "ens33" {
            println!("Name: {}", interface.name);
            println!("Index: {}", interface.index);
            println!("MAC Address: {:?}", interface.mac);
            println!("IP Addresses: {:?}", interface.ips);
            println!("Flags: {:?}", interface.flags);
        }
    }

    let interface = interfaces
        .iter()
        .find(|iface| {
            iface.name == "ens33"
                && !iface.is_loopback()
        })
        .expect("No suitable network interface found");

    let ipv4_source: Ipv4Addr = Ipv4Addr::new( 192,168,11,129);
    let icmp_destination: Ipv4Addr = Ipv4Addr::new( 172,31,36,33);

    // IP Header 中不包含选项
    let ipv4_header_len = 20;
    // TCP Header 中不包含选项，比如 TSVal 等
    let udp_header_len = 8;

    let total_length: u16 = (ipv4_header_len + udp_header_len + 32) as _;

    let mut ethernet_buffer = [0u8; 14];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::new(0x00,0x50,0x56,0xfe,0x22,0xec));
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    println!("{:?}", ethernet_packet);

    let mut ipv4_buffer = [0u8; 20];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_dscp(1);
    ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length(total_length);
    ipv4_packet.set_identification(14599);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_source(ipv4_source);
    ipv4_packet.set_destination(icmp_destination);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_checksum(0);

    let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(0x1);
    icmp_packet.set_sequence_number(0x53);
    let data: &[u8] = &[
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69,
    ];
    icmp_packet.set_payload(data);
    let icmp_checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_checksum);

    println!("icmp:{:?}", icmp_packet.packet());

    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(ethernet_packet.packet());
    final_packet.extend_from_slice(ipv4_packet.packet());
    final_packet.extend_from_slice(icmp_packet.packet());

    println!("{:?}", final_packet);

    // println!("{:?}",final_packet);
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    tx.send_to(&final_packet, None);
    // let handle1 = thread::spawn(move|| {
    //     loop {
    //         let res = tx.send_to(&final_packet, None);

    //         match res {
    //             Some(Ok(())) => println!("Packet sent successfully"),
    //             Some(Err(e)) => println!("Failed to send packet: {}", e),
    //             None => println!("No destination interface specified"),
    //         }

    //         thread::sleep(Duration::from_secs(2));
    //     }
    // });

    let handle2 = thread::spawn(move || loop {
        match rx.next() {
            Ok(received) => {
                let ethernet_packet = EthernetPacket::new(received).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Udp => {
                                let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                                if udp_packet.get_source() == 53 || udp_packet.get_destination() == 53 {
                                    println!("recv dns packet: sourse port: {}, dest port: {} ", udp_packet.get_source(), udp_packet.get_destination());
                                    
                                    // 反转源目 IP 地址
                                    let source_ip = ipv4_packet.get_source();
                                    let destination_ip = ipv4_packet.get_destination();
                                    
                                    // 创建一个可变的以太网帧缓冲区
                                    let mut ethernet_buffer = vec![0u8; ethernet_packet.packet().len()];
                                    let mut new_ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                                    
                                    // 手动复制以太网帧字段
                                    new_ethernet_packet.set_destination(ethernet_packet.get_source());
                                    new_ethernet_packet.set_source(ethernet_packet.get_destination());
                                    new_ethernet_packet.set_ethertype(ethernet_packet.get_ethertype());
                                    
                                    // 创建一个可变的 IPv4 包缓冲区
                                    let mut ipv4_buffer = vec![0u8; ipv4_packet.packet().len()];
                                    let mut new_ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                                    
                                    // 手动复制 IPv4 包字段并反转源目 IP
                                    new_ipv4_packet.set_version(ipv4_packet.get_version());
                                    new_ipv4_packet.set_header_length(ipv4_packet.get_header_length());
                                    new_ipv4_packet.set_dscp(ipv4_packet.get_dscp());
                                    new_ipv4_packet.set_ecn(ipv4_packet.get_ecn());
                                    new_ipv4_packet.set_total_length(ipv4_packet.get_total_length());
                                    new_ipv4_packet.set_identification(ipv4_packet.get_identification());
                                    new_ipv4_packet.set_flags(ipv4_packet.get_flags());
                                    new_ipv4_packet.set_fragment_offset(ipv4_packet.get_fragment_offset());
                                    new_ipv4_packet.set_ttl(ipv4_packet.get_ttl());
                                    new_ipv4_packet.set_next_level_protocol(ipv4_packet.get_next_level_protocol());
                                    new_ipv4_packet.set_checksum(ipv4_packet.get_checksum());
                                    new_ipv4_packet.set_source(destination_ip);
                                    new_ipv4_packet.set_destination(source_ip);
                                    
                                    // 创建一个可变的 UDP 包缓冲区
                                    let mut udp_buffer = vec![0u8; udp_packet.packet().len()];
                                    let mut new_udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
                                    
                                    // 手动复制 UDP 包字段
                                    new_udp_packet.set_source(udp_packet.get_destination());
                                    new_udp_packet.set_destination(udp_packet.get_source());
                                    new_udp_packet.set_length(udp_packet.get_length());
                                    new_udp_packet.set_checksum(udp_packet.get_checksum());
                                    new_udp_packet.set_payload(udp_packet.payload());
                                    
                                    // 将新的 UDP 包 payload 设置到新的 IPv4 包中
                                    new_ipv4_packet.set_payload(new_udp_packet.packet());
                                    
                                    // 将新的 IPv4 包 payload 设置到新的以太网帧中
                                    new_ethernet_packet.set_payload(new_ipv4_packet.packet());
                                    
                                    // 发送新的以太网帧
                                    match tx.send_to(new_ethernet_packet.packet(), None) {
                                        Some(_) => println!("send tranform DNS packet success"),
                                        None => println!("send tranform DNS packet failure"),
                                    }
                                    thread::sleep(Duration::from_secs(3))
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {},
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
    });

    // // 等待两个线程完成
    // handle1.join().unwrap();
    // handle2.join().unwrap();
}

fn send_by_datalink() {
    let interfaces = datalink::interfaces();

    for interface in interfaces.iter() {
        if interface.name == "ens33" {
            println!("Name: {}", interface.name);
            println!("Index: {}", interface.index);
            println!("MAC Address: {:?}", interface.mac);
            println!("IP Addresses: {:?}", interface.ips);
            println!("Flags: {:?}", interface.flags);
        }
    }

    let interface = interfaces
        .iter()
        .find(|iface| {
            iface.name == "ens33"
                && !iface.is_loopback()
        })
        .expect("No suitable network interface found");

    let dns_query: Vec<u8> = build_dns_query("www.baidu.com");

    let dns_query_len = dns_query.len();

    let ipv4_source: Ipv4Addr = Ipv4Addr::new(192,168,11,129);
    let ipv4_destination: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

    // IP Header 中不包含选项
    let ipv4_header_len = 20;
    // TCP Header 中不包含选项，比如 TSVal 等
    let udp_header_len = 8;

    let total_length: u16 = (ipv4_header_len + udp_header_len + dns_query_len) as _;

    let mut ethernet_buffer = [0u8; 14];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::new(0x00,0x50,0x56,0xfe,0x22,0xec));
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_buffer = [0u8; 20];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_dscp(1);
    ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length(total_length);
    ipv4_packet.set_identification(21482);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);

    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_source(ipv4_source);
    ipv4_packet.set_destination(ipv4_destination);
    ipv4_packet.set_ttl(200);
    ipv4_packet.set_checksum(0);

    let mut udp_buffer: Vec<u8> = vec![0u8; 8];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.set_source(61669);
    udp_packet.set_destination(53);
    udp_packet.set_length(8 + dns_query.len() as u16);
    let um_checksum = ipv4_checksum(&udp_packet.to_immutable(), &ipv4_source,&ipv4_destination);
    udp_packet.set_checksum(um_checksum);
    // udp_packet.set_checksum(0xe088);

    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(ethernet_packet.packet());
    final_packet.extend_from_slice(ipv4_packet.packet());
    final_packet.extend_from_slice(udp_packet.packet());
    final_packet.extend_from_slice(&dns_query);

    // println!("{:?}",final_packet);
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let res = tx.send_to(&final_packet, None);

    match res {
        Some(Ok(())) => println!("Packet sent successfully"),
        Some(Err(e)) => println!("Failed to send packet: {}", e),
        None => println!("No destination interface specified"),
    }

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                let dns_payload = udp.payload();
                                if let Some(dns) = DnsPacket::new(dns_payload) {
                                    // 解析 DNS 查询
                                    for query in dns.get_queries() {
                                        if let domain = query.get_qname_parsed() {
                                            if domain.contains("test.com") {
                                                println!("Found DNS query for: {}", domain);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            },
            Err(e) => {
                println!(
                    "An error occurred when reading from the datalink channel: {}",
                    e
                );
                continue;
            }
        }
    }
}

const DNS_SERVER_IP: &str = "8.8.8.8"; // Google DNS
const DNS_PORT: u16 = 53;

fn send_by_tranport() {
    // 获取网络接口

    // 构建 DNS 请求报文
    let dns_request = build_dns_query("www.baidu.com");

    // 创建 UDP 套接字并发送请求
    let socket = std::net::UdpSocket::bind("0.0.0.0:15632").expect("Failed to bind socket");
    socket
        .send_to(&dns_request, (DNS_SERVER_IP, DNS_PORT))
        .expect("Failed to send DNS request");

    // 接收响应
    let mut buffer = [0; 512];
    let (size, _src) = socket
        .recv_from(&mut buffer)
        .expect("Failed to receive DNS response");

    // 解析 DNS 响应
    println!("Received DNS response: {:?}", &buffer[..size]);
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut buffer = Vec::new();

    // DNS Header
    buffer.extend_from_slice(&[0x33, 0x01]); // Transaction ID
    buffer.extend_from_slice(&[0x01, 0x00]); // Flags (standard query)
    buffer.extend_from_slice(&[0x00, 0x01]); // Questions
    buffer.extend_from_slice(&[0x00, 0x00]); // Answer RRs
    buffer.extend_from_slice(&[0x00, 0x00]); // Authority RRs
    buffer.extend_from_slice(&[0x00, 0x00]); // Additional RRs

    for label in domain.split('.') {
        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }

    buffer.extend_from_slice(&[0x00]); // Null terminator for the domain name

    // Type and Class
    buffer.extend_from_slice(&[0x00, 0x01]); // Type A
    buffer.extend_from_slice(&[0x00, 0x01]); // Class IN

    buffer
}
