use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::dns::DnsPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use std::sync::mpsc;

pub fn recv(device: String, flag_id: u16, retry_chan: mpsc::Sender<()>) {
    let interfaces = datalink::interfaces();

    let interface = interfaces
        .iter()
        .find(|iface| iface.name == device && !iface.is_loopback())
        .expect("No suitable network interface found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
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
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                let source = udp.get_source();
                                if source != 53 {
                                    continue;
                                }
                                let dns_payload = udp.payload();
                                if let Some(dns) = DnsPacket::new(dns_payload) {
                                    
                                    for query in dns.get_queries() {
                                        println!("Found DNS query for: {}", query.get_qname_parsed());
                                    }

                                    // println!("{:?}", dns.get_queries());
                                    // 解析 DNS 查询
                                    if dns.get_is_response() != 1 {
                                        continue;
                                    }
                                    // println!("{:?}", dns);
                                    // println!("{:?}", dns);

                                    // for resp in dns.get_responses(){
                                    //     println!("{:?}",resp.data.as_slice());
                                    // }

                                    // if dns.get_queries().len() <= 0 {
                                    //     continue;
                                    // }

                                    // if dns.get_id() / 100 == flag_id {
                                    //     if dns.get_query_count() > 0 {
                                    //         for query in dns.get_queries() {
                                    //             let domain = query.get_qname_parsed();
                                    //             println!("Found DNS query for: {}", domain);
                                    //         }
                                    //     }
                                    // }
                                }
                            }
                        }
                    }
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
}
