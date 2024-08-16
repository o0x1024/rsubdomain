use pnet::packet::{
    icmp::{
        echo_reply::EchoReplyPacket,
        echo_request::{IcmpCodes, MutableEchoRequestPacket},
        IcmpTypes,
    },
    ip::IpNextHeaderProtocols,
    util, Packet,
};
use pnet::transport::{icmp_packet_iter,TransportChannelType::Layer4,transport_channel,TransportProtocol};

use rand::random;
use std::{
    env,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const ICMP_SIZE: usize = 64;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: icmp-demo target_ip");
    }
    let target_ip: IpAddr = args[1].parse().unwrap();
    println!("icpm echo request to target ip:{:#?}", target_ip);

    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e)  => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
        let icmp_packet = create_icmp_packet(&mut icmp_header);
        let identifier = icmp_packet.get_identifier();
        let timer = Arc::new(RwLock::new(Instant::now()));
        tx.send_to(icmp_packet, target_ip).unwrap();

        match iter.next() {
            Ok((packet, addr)) => match EchoReplyPacket::new(packet.packet()) {
                Some(echo_reply) => {
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        let start_time = timer.read().unwrap();
                        let rtt = Instant::now().duration_since(*start_time);
                        println!(
                            "ICMP EchoReply received from {:?}: {:?} , Time:{:?}, Identifier: {} => {}",
                            addr,
                            packet.get_icmp_type(),
                            rtt,
                            identifier,
                            echo_reply.get_identifier()
                        );
                    } else {
                        println!(
                            "ICMP type other than reply (0) received from {:?}: {:?}",
                            addr,
                            packet.get_icmp_type()
                        );
                    }
                }
                None => {}
            },
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    //Ok(())
}

fn create_icmp_packet<'a>(icmp_header: &'a mut [u8]) -> MutableEchoRequestPacket<'a> {
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(1);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);
    icmp_packet
}