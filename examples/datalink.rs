use pnet::{
    packet::{
        arp::{ArpHardwareTypes, ArpOperations},
        ethernet::EtherTypes,
        Packet,
    },
    util::MacAddr,
};
use std::net::Ipv4Addr;

fn main() {
    // debug options
    std::env::set_var("RUST_BACKTRACE", "1");

    // get all the interfaces and everything

    let interfac = pnet::datalink::interfaces()[1].clone();
    println!("the interface name is {}", interfac.name);
    let (mut tx, mut _rx) = match pnet::datalink::channel(&interfac, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    // custom code...
    let mut etherbuff = [0u8; 42];
    let mut arpbuff = [0u8; 28];

    let (mut tx, _rx) = match pnet::datalink::channel(&interfac, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    let mut my_arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut arpbuff)
        .expect("could not create arp packet");
    my_arp_packet.set_operation(ArpOperations::Request);
    my_arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    my_arp_packet.set_protocol_type(EtherTypes::Ipv4);
    my_arp_packet.set_hw_addr_len(6);
    my_arp_packet.set_proto_addr_len(4);
    my_arp_packet.set_sender_hw_addr(interfac.mac.unwrap());
    my_arp_packet.set_sender_proto_addr(Ipv4Addr::new(192, 168, 100, 16));
    my_arp_packet.set_target_proto_addr(Ipv4Addr::new(192, 168, 100, 14));

    let mut my_ethernet_packet =
        pnet::packet::ethernet::MutableEthernetPacket::new(&mut etherbuff).unwrap();

    my_ethernet_packet.set_destination(MacAddr::broadcast());
    my_ethernet_packet.set_source(MacAddr::new(0x9c, 0x29, 0x76, 0x7a, 0x70, 0x7e));
    my_ethernet_packet.set_ethertype(EtherTypes::Arp); // for ethernet
    my_ethernet_packet.set_payload(my_arp_packet.packet());

    tx.send_to(&etherbuff, Some(interfac.clone()));
}
