use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

use pnet::packet::{
    dns::{DnsPacket, DnsTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    Packet,
};

use crate::{
    send,
    structs::{LOCAL_STACK, LOCAL_STATUS},
};

pub fn handle_dns_packet(
    dns_recv: mpsc::Receiver<Arc<Vec<u8>>>,
    print_status: bool,
    flag_id: u16,
    running: Arc<AtomicBool>,
    slient: bool,
) {
    let mut domain_list: Vec<String> = Vec::new();
    let mut ip_list: Vec<String> = Vec::new();

    while running.load(Ordering::Relaxed) {
        match dns_recv.recv() {
            Ok(ipv4_packet) => {
                if let Some(ipv4) = Ipv4Packet::new(ipv4_packet.as_ref()) {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if let Some(dns) = DnsPacket::new(udp.payload()) {
                                let mut query_name: String = String::new();
                                if dns.get_is_response() == 0 {
                                    continue;
                                }
                                let tid = dns.get_id() / 100;
                                if tid == flag_id {
                                    if dns.get_response_count() > 0 {
                                        query_name = dns.get_queries()[0].get_qname_parsed();

                                        for res in dns.get_responses() {
                                            match res.rtype {
                                                DnsTypes::A => {
                                                    let query_name_clone = query_name.clone();
                                                    let ipaddr =  res.data
                                                    .iter()
                                                    .map(|byte| byte.to_string())
                                                    .collect::<Vec<String>>()
                                                    .join(".");
                                                    if print_status  {
                                                        if slient{
                                                            println!("{}",query_name);
                                                        }else{
                                                            println!(
                                                                "{} =>  {}",
                                                                query_name,
                                                                ipaddr
                                                            );
                                                        }

                                                    }

                                                    domain_list.push(query_name_clone);
                                                    ip_list.push(ipaddr);
                                                }
                                                DnsTypes::CNAME => {
                                                    if print_status && !slient {
                                                        println!(
                                                            "{} => CNAME {:?}",
                                                            query_name, res.data
                                                        );
                                                    }
                                                }
                                                _ => (),
                                            }
                                        }
                                    }
                                    match LOCAL_STATUS.write() {
                                        Ok(mut local_status) => {
                                            let index = send::generate_map_index(
                                                dns.get_id() % 100,
                                                udp.get_destination(),
                                            );
                                            match local_status
                                                .search_from_index_and_delete(index as u32)
                                            {
                                                Ok(data) => {
                                                    // println!("[+] delete recv:{:?}", data.v);
                                                }
                                                Err(_) => (),
                                            }

                                            match LOCAL_STACK.try_write() {
                                                Ok(mut stack) => {
                                                    if stack.length <= 50000 {
                                                        stack.push(index as usize)
                                                    }
                                                }
                                                Err(_) => (),
                                            }
                                        }
                                        Err(_) => (),
                                    };
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => (),
        }
    }
}

// let tid = dns.get_id() / 100;
// if tid == flag_id {
//     if dns.get_response_count() > 0 {
//         for query in dns.get_queries() {
//             query_name.push_str(
//                 query.get_qname_parsed().as_str(),
//             )
//         }
//         for res in dns.get_responses() {
//             match res.rtype{
//                 DnsTypes::A =>{
//                     println!(
//                         "{} =>  {}",
//                         query_name, res.data.iter().map(|byte| byte.to_string()).collect::<Vec<String>>().join(".")
//                     );
//                 },
//                 DnsTypes::CNAME =>{

//                     println!(
//                         "{} => CNAME {:?}",
//                         query_name, res.data
//                     );
//                 }
//                 _ =>()
//             }
//         }
//     }
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

// }
