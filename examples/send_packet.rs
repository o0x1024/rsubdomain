use pnet::datalink;
use pnet::packet::dns::MutableDnsPacket;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::gre::U16BE;
use pnet::packet::icmp::echo_reply::IcmpCodes;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ipv4::Ipv4Flags::{self, DontFragment};
use pnet::packet::ipv4:: MutableIpv4Packet;
use pnet::packet::udp::{self, ipv4_checksum, MutableUdpPacket};
use pnet::packet::{ip::IpNextHeaderProtocols, util, Packet};
use pnet::transport::{transport_channel, TransportProtocol};
use pnet::transport::TransportChannelType::Layer4;

use pnet::util::MacAddr;

use rsubdomain::device;
use rsubdomain::model::EthTable;

use std::borrow::BorrowMut;
use std::net::Ipv4Addr;

use pnet::datalink::Channel::Ethernet;

#[tokio::main]
async fn main() {
    // 获取网络接口
    let ether = device::auto_get_devices();
    println!("{:?}", ether);
    let flg = 2;

    if flg == 1 {
        send_by_tranport();
    } else if flg == 2 {
        send_by_datalink(ether, "8.8.8.8");
    } else {
        send_icmp_datalink(ether, "172.31.36.33");
    }

}
const ICMP_SIZE: usize = 40;

fn send_by_datalink(ether: EthTable, dst_ip: &str) {
    let interfaces = datalink::interfaces();

    for itn in interfaces.clone(){
        println!("{:?}",itn);
    }

    let interface = interfaces
        .iter()
        .find(|iface| iface.name == ether.device && !iface.is_loopback())
        .expect("No suitable network interface found");

    let dns_query: Vec<u8> = build_dns_query("1Uixxx6.example.com");
    let dns_query_len = dns_query.len();

    let ipv4_source: Ipv4Addr = ether.src_ip;
    let ipv4_destination: Ipv4Addr = dst_ip.parse().unwrap();

    let ipv4_header_len = 20;
    let udp_header_len = 8;

    let total_length: u16 = (ipv4_header_len + udp_header_len + dns_query_len) as _;


    // let mut udp_buffer: Vec<u8> = vec![0u8; 42];
    let mut udp_buffer: Vec<u8> = Vec::with_capacity(8 + dns_query_len);
    udp_buffer.resize(8 + dns_query_len, 0u8);

    let mut udp_header = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_header.set_source(rand::random::<u16>());
    udp_header.set_destination(53);
    udp_header.set_length(8 + dns_query.len() as u16);
    udp_header.set_payload(&dns_query);

    let mut ipv4_buffer = [0u8; 20];
    let mut ipv4_header = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_header.set_header_length(5);
    ipv4_header.set_total_length(total_length);
    ipv4_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_header.set_source(ipv4_source);
    ipv4_header.set_destination(ipv4_destination);
    ipv4_header.set_identification(5636);
    ipv4_header.set_ttl(64);
    ipv4_header.set_version(4);
    ipv4_header.set_flags(Ipv4Flags::DontFragment);


    let mut ethernet_buffer = [0u8; 14];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(ether.dst_mac);
    // ethernet_packet.set_destination(MacAddr(0xb0,0x7b,0x25,0x24,0x95,0x49));
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);


    let checksum = pnet::packet::ipv4::checksum(&ipv4_header.to_immutable());
    ipv4_header.set_checksum(checksum);

    let checksum = ipv4_checksum(&udp_header.to_immutable(), &ipv4_source, &ipv4_destination);
    udp_header.set_checksum(checksum);

    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(ethernet_packet.packet());
    final_packet.extend_from_slice(ipv4_header.packet());
    final_packet.extend_from_slice(udp_header.packet());
    // final_packet.extend_from_slice(&dns_query);

    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let res = tx.send_to(&final_packet, None);

    match res {
        Some(Ok(())) => (),
        Some(Err(e)) => println!("Failed to send packet: {}", e),
        None => println!("No destination interface specified"),
    }

    println!("--1");

}



fn send_by_tranport() {
    // 获取网络接口
    let dsp_ip = "8.8.8.8";

    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(_) => return (),
    };

    // 构建 DNS 请求报文
    let mut dns_request = build_dns_query("www.test.com");

    let packet = MutableDnsPacket::new(&mut dns_request).unwrap();

    tx.send_to(packet, dsp_ip.parse().unwrap());

    println!(":123123")
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


fn send_icmp_datalink(ether: EthTable, dst_ip: &str) {
    let interfaces = datalink::interfaces();

    let interface = interfaces
        .iter()
        .find(|iface| iface.name == ether.device && !iface.is_loopback())
        .expect("No suitable network interface found");

    let ipv4_source: Ipv4Addr = ether.src_ip;
    let icmp_destination: Ipv4Addr = dst_ip.parse().unwrap();

    // IP Header 中不包含选项
    let ipv4_header_len = 20;
    // TCP Header 中不包含选项，比如 TSVal 等
    let udp_header_len = 8;

    let total_length: u16 = (ipv4_header_len + udp_header_len + 32) as _;

    let mut ethernet_buffer = [0u8; 14];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    // ethernet_packet.set_destination(MacAddr::new(0x68, 0xa8, 0x28, 0x2f, 0xd7, 0x07));
    ethernet_packet.set_destination(MacAddr(0xb0, 0x7b, 0x25, 0x24, 0x95, 0x49));

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

    ipv4_packet.set_flags(DontFragment);
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
}
