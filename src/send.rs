use crate::model::{EthTable, StatusTable};
use crate::stack::LOCAL_STACK;
use crate::local_struct::LOCAL_STATUS;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkSender};
use pnet::packet::dns::{
    DnsClasses, DnsQuery, DnsTypes, MutableDnsPacket,
    Opcode,
};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use rand::Rng;
use std::cell::RefCell;
use std::time::Duration;
use std::{i32, thread};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Mutex;


// use crate::model::StatusTable;

#[derive(Clone)]
pub struct SendDog {
    ether: EthTable,
    dns: Vec<String>,
    handle: Rc<RefCell<Box<dyn DataLinkSender>>>,
    print_status: bool,
    index: u16,
    lock: Rc<Mutex<()>>,
    increate_index: bool,
    flag_id: u16,
    flag_id2: u16,
}

impl SendDog {
    pub fn new(ether: EthTable, dns: Vec<String>, flag_id: u16, print_status: bool) -> SendDog {


        
        let interfaces = datalink::interfaces();

        let interface = interfaces
            .iter()
            .find(|iface| iface.name == ether.device && !iface.is_loopback())
            .expect("No suitable network interface found");

        let (mut _handle, _) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let handle: Rc<RefCell<Box<dyn DataLinkSender>>> = Rc::new(RefCell::new(_handle));

        let default_dns: Vec<String>;
        if dns.len() == 0 {
            default_dns = vec![
                "10.1.172.76".to_string(),
                // "223.5.5.5".to_string(),
                // "223.6.6.6".to_string(),
                // "180.76.76.76".to_string(),
                // "119.29.29.29".to_string(),
                // "182.254.116.116".to_string(),
                // "114.114.114.115".to_string(),
            ];
        } else {
            default_dns = dns;
        }

        SendDog {
            ether,
            dns: default_dns,
            flag_id,
            print_status,
            handle,
            index: 10000,
            lock: Mutex::new(()).into(),
            increate_index: true,
            flag_id2: 0,
        }
    }

    pub fn chose_dns(&self) -> String {
        // let mut rng = rand::thread_rng();
        // let index = rng.gen_range(0..self.dns.len() - 1);
        self.dns[0].to_owned()
    }

    pub fn send(&self, domain: String, dnsname: String, src_port: u16, flag_id: u16) {
        let dns_query: Vec<u8> = build_dns_query(domain.as_str(), flag_id);
        let dns_query_len = dns_query.len();
        let ipv4_source: Ipv4Addr = self.ether.src_ip;
        let ipv4_destination: Ipv4Addr = dnsname.parse().unwrap();

        // IP Header 中不包含选项
        let ipv4_header_len = 20;
        // TCP Header 中不包含选项，比如 TSVal 等
        let udp_header_len = 8;

        let total_length: u16 = (ipv4_header_len + udp_header_len + dns_query_len) as _;

        let mut ethernet_buffer = [0u8; 14];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(self.ether.dst_mac);
        ethernet_packet.set_source(self.ether.src_mac);
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
        ipv4_packet.set_destination(Ipv4Addr::from_str(dnsname.as_str()).unwrap());
        ipv4_packet.set_ttl(200);
        ipv4_packet.set_checksum(0);

        let mut udp_buffer: Vec<u8> = vec![0u8; 8];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(src_port);
        udp_packet.set_destination(53);
        udp_packet.set_length(8 + dns_query.len() as u16);
        let um_checksum =
            ipv4_checksum(&udp_packet.to_immutable(), &ipv4_source, &ipv4_destination);
        udp_packet.set_checksum(um_checksum);
        // udp_packet.set_checksum(0xe088);

        let mut final_packet = Vec::new();
        final_packet.extend_from_slice(ethernet_packet.packet());
        final_packet.extend_from_slice(ipv4_packet.packet());
        final_packet.extend_from_slice(udp_packet.packet());
        final_packet.extend_from_slice(&dns_query);

        let res = {
            let mut handle = self.handle.borrow_mut();
            handle.send_to(&final_packet, None)
            // self.handle.send_to(&final_packet, None);
        };

        match res {
            Some(Ok(())) => (),
            Some(Err(e)) => println!("Failed to send packet: {}", e),
            None => println!("No destination interface specified"),
        }
    }

    pub fn build_status_table(&mut self, domain: &str, dns: &str, domain_level: isize) -> (u16, u16) {
        let _lock = self.lock.lock().unwrap(); // 锁定
        let mut stack = LOCAL_STACK.write().unwrap();
        if self.index >= 60000 {
            self.flag_id2 += 1;
            self.index = 10000;
        }
        if self.flag_id2 > 99 {
            self.increate_index = false;
        }
        if self.increate_index {
            self.index += 1;
        } else {
            loop {
                match stack.pop() {
                    Some(v) => {
                        let (flag_id2, index) = generate_flag_index_from_map(v);
                        self.flag_id2 = flag_id2;
                        self.index = index;
                        break;
                    }
                    None => {
                        thread::sleep(Duration::from_millis(520));
                    }
                }
            }
        }

        let index = generate_map_index(self.flag_id2, self.index);
        let status = StatusTable {
            domain: domain.to_string(),
            dns: dns.to_string(),
            time: chrono::Utc::now().timestamp() as u64, // 使用 chrono crate 获取当前时间
            retry: 0,
            domain_level,
        };

        let mut local_status = LOCAL_STATUS.write().unwrap();
        local_status.append(status, index as u32);
        (self.flag_id2, self.index)
    }
}

fn generate_map_index(flag_id2: u16, index: u16) -> i32 {
    // 由 flag_id2 和 index 生成 map 中的唯一 id
    (flag_id2 as i32 * 60000) + (index as i32)
}


fn generate_flag_index_from_map(index: usize) -> (u16, u16) {
    // 从已经生成好的 map index 中返回 flag_id 和 index
    let yuzhi: usize = 60000;
    let flag2 = index / yuzhi;
    let index2 = index % yuzhi;
    (flag2 as u16, index2 as u16)
}


fn build_dns_query(domain: &str, flag_id: u16) -> Vec<u8> {
    let mut buffer = Vec::new();

    // DNS Header
    buffer.push((flag_id >> 8) as u8); // 高8位
    buffer.push(flag_id as u8); // 低8位
    // buffer.extend_from_slice(&[0x33, 0x01]); // Transaction ID
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


// fn build_dns_query(domain: &str, flag_id: u16) -> Vec<u8> {
//     let mut buffer = vec![0; 512];
//     let mut dns_packet = MutableDnsPacket::new(&mut buffer ).unwrap();
//     dns_packet.set_id(flag_id);
//     dns_packet.set_is_response(0);
//     dns_packet.set_opcode(Opcode::new(0));
//     dns_packet.set_is_truncated(0);
//     dns_packet.set_is_recursion_desirable(0);
//     dns_packet.set_zero_reserved(0);
//     dns_packet.set_is_non_authenticated_data(0);
//     dns_packet.set_additional_rr_count(0);
//     dns_packet.set_authority_rr_count(0);
//     dns_packet.set_is_answer_authenticated(0);



//     let query1 = DnsQuery {
//         qname: domain.as_bytes().to_vec(),
//         qtype: DnsTypes::A,
//         qclass: DnsClasses::IN,
//         payload: Vec::new(),
//     };

//     let queries = &[query1];

//     dns_packet.set_queries(queries);
    
//     dns_packet.packet().to_vec()
// }
