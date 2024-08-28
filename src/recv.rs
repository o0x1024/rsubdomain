use crate::send;
use crate::structs::{LOCAL_STACK, LOCAL_STATUS};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::dns::{DnsPacket, DnsTypes};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use std::sync::{mpsc, Arc, Mutex};

pub fn recv(device: String, flag_id: u16, retry_chan: mpsc::Receiver<()>,running:Arc<Mutex<bool>>) {
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

    let mut recv_count = 0 ;
    let mut count = 0;
    loop {
        // match running.try_lock(){
        //     Ok( running) =>{
        //         if!*running{
        //             return;
        //         }
        //     }
        //     Err(_) =>()
        // }
        

        match rx.next() {
            Ok(packet) => {
                // if retry_chan.try_recv().is_ok() {
                //     println!("Exiting recv loop.");
                //     break;
                // }

                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                let dns_payload = udp.payload();
                                if let Some(dns) = DnsPacket::new(dns_payload) {
                                    let mut query_name: String = String::new();
                                    if dns.get_is_response() == 0 {
                                        continue;
                                    }
                                    let tid = dns.get_id() / 100;
                                    if tid == flag_id {

                                        if dns.get_response_count() > 0 {
                                            for query in dns.get_queries() {

                                                query_name.push_str(
                                                    query.get_qname_parsed().as_str(),
                                                )
                                            }
                                            for res in dns.get_responses() {
                                                match res.rtype{
                                                    DnsTypes::A =>{
                                                        println!(
                                                            "{} =>  {}",
                                                            query_name, res.data.iter().map(|byte| byte.to_string()).collect::<Vec<String>>().join(",")
                                                        );
                                                    },
                                                    DnsTypes::CNAME =>{
                                                        println!(
                                                            "{} => CNAME {:?}",
                                                            query_name, res.data
                                                        );
                                                    }
                                                    _ =>()
                                                }
                                            }

                                        }
                                        // match LOCAL_STATUS.try_write() {
                                        //     Ok(mut local_status) => {
                                        //         let index = send::generate_map_index(
                                        //             dns.get_id() % 100,
                                        //             udp.get_destination(),
                                        //         );
                                        //         match local_status
                                        //             .search_from_index_and_delete(index as u32)
                                        //         {
                                        //             Ok(data) => {
                                        //                 // println!("delete:{:?}", data.v);
                                        //                 count += 1;
                                        //             }
                                        //             Err(_) => (),
                                        //         }

                                        //         if count/50 == 0{
                                        //             println!("delete:{}", count);

                                        //         }

                                        //         match LOCAL_STACK.try_write() {
                                        //             Ok(mut stack) => {
                                        //                 if stack.length <= 50000 {
                                        //                     stack.push(index as usize)
                                        //                 }
                                        //             }
                                        //             Err(_) => (),
                                        //         }


                                        //         if dns.get_response_count() > 0 {
                                        //             for query in dns.get_queries() {
                                        //                 if query.get_qname_parsed() == "mail.mgtv.com"{
                                        //                     println!("{} ", query.get_qname_parsed());
                                        //                 }
                                        //                 query_name.push_str(
                                        //                     query.get_qname_parsed().as_str(),
                                        //                 )
                                        //             }
                                        //             for res in dns.get_responses() {
                                        //                 if res.rtype == DnsTypes::A {
                                        //                     println!(
                                        //                         "{} -> {:?}",
                                        //                         query_name, res.data
                                        //                     );
                                        //                 }
                                        //             }
                                        //         }
                                        //     }
                                        //     Err(_) => (),
                                        // };

                                    }
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
