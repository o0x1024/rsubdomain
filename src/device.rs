use pnet::{datalink, packet::{dns::DnsPacket, ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket, Packet}};
use std::{
     net::IpAddr, process::Command, sync::mpsc::{Receiver, Sender}, thread::{self, JoinHandle}
};
use std::sync::mpsc;
use pnet::packet::ethernet::EthernetPacket;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::iter::repeat_with;

use pnet::datalink::Channel::Ethernet;
use crate::model::EthTable;



pub fn auto_get_devices() ->EthTable{
    let interfaces = datalink::interfaces();
    let (mptx, mprx):(Sender<EthTable>,Receiver<EthTable>) = mpsc::channel();
    let domain = random_str(4)+".example.com";
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for interface in interfaces {
        if !interface.is_loopback() {
            for ip in interface.ips.clone() {
                match ip.ip() {
                    IpAddr::V4(_) => {

                        let domain_clone=domain.clone();
                        let interface_clone = interface.clone();
                        let interface_name = interface.name.clone();
                        let mptx_clone = mptx.clone();
                        let handle = thread::spawn(move||{
                            let (_, mut rx) = match datalink::channel(&interface_clone, Default::default()) {
                                Ok(Ethernet(_tx, _rx)) => (_tx, _rx),
                                Ok(_) => panic!("Unhandled channel type"),
                                Err(e) => panic!("An error occurred when creating the datalink channel: {}",e)
                            };
                            loop {
                                match rx.next() {
                                    Ok(packet) => {
                                        let ethernet = EthernetPacket::new(packet).unwrap();
                                        match ethernet.get_ethertype()  {
                                            EtherTypes::Ipv4 =>{
                                                let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
                                                match ipv4_packet.get_next_level_protocol() {
                                                    IpNextHeaderProtocols::Udp =>{

                                                        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                                                        if let Some(dns) = DnsPacket::new(udp_packet.payload()){

                                                            for query in dns.get_queries() {
                                                                let recv_domain = query.get_qname_parsed();
                                                                    if recv_domain.contains(&domain_clone) {
                                                                        let ipv4 = match ip.ip() {
                                                                            IpAddr::V4(addr) => addr,
                                                                            IpAddr::V6(_) => panic!("Expected an IPv4 address, got an IPv6 address"),
                                                                        };
                                                                        if let Err(err) =  mptx_clone.send(EthTable{src_ip:ipv4,device:interface_name,src_mac:ethernet.get_source(),dst_mac:ethernet.get_destination()}){
                                                                            println!("An error occurred when sending the message: {}", err);
                                                                        }
                                                                        return
                                                                    }
                                                            }
                                                        }
                                                    }
                                                    _ => (),
                                                }
                                            }
                                            _ => (),
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
                        });
                        handles.push(handle);
                    },
                    _ => (),
                }
            }
        }
    }

    Command::new("nslookup").arg(domain).output().expect("failed to execute process");

    match mprx.recv() {
        Ok(eth) => {
            // println!("eth: {:?}", eth);
            eth
        },
        Err(e) => {
            panic!("recv error:{}",e)
        }
    }
    // let eth: EthTable =  mprx.recv().unwrap();
}

// fn build_dns_packet() -> &[u8] {
    
// }



fn random_str(n: usize) -> String {
    let mut rng = thread_rng();
    // 生成一个长度为 n 的随机字符串
    repeat_with(|| rng.sample(Alphanumeric) as char)
        .take(n)
        .collect()
}