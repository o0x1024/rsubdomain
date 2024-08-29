use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};

pub fn recv(device: String, dns_send: mpsc::Sender<Arc<Vec<u8>>>, running: Arc<AtomicBool>) {
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

    while running.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let ipv4_data = ipv4.packet().to_vec();
                        let cloned_ipv4: Arc<Vec<u8>> = Arc::new(ipv4_data);
                        match dns_send.send(cloned_ipv4) {
                            Ok(_) => {}
                            Err(e) => println!("Failed to send packet: {}", e),
                        }
                    }
                }
            }
            Err(e) => {
                println!(
                    "An error occurred when reading from the datalink channel: {}",
                    e
                );
                break;
            }
        }
    }
}
