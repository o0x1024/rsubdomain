use log::{error, warn};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::Duration;
use trust_dns_resolver::proto::op::{Message, MessageType};

pub fn recv(
    device: String,
    local_ip: Ipv4Addr,
    dns_servers: Vec<String>,
    flag_id: u16,
    dns_send: mpsc::Sender<Arc<Vec<u8>>>,
    running: Arc<AtomicBool>,
) {
    let interfaces = datalink::interfaces();
    let resolver_ips = dns_servers
        .into_iter()
        .filter_map(|server| server.parse::<Ipv4Addr>().ok())
        .collect::<Vec<_>>();

    let interface = match interfaces
        .iter()
        .find(|iface| iface.name == device && !iface.is_loopback())
    {
        Some(iface) => iface,
        None => {
            error!("网络接口 '{}' 未找到", device);
            return;
        }
    };

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(1000)), // 设置读取超时
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            error!("通道类型不支持");
            return;
        }
        Err(error) => {
            error!("创建数据链路通道失败: {}", error);
            return;
        }
    };

    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;

    while running.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                consecutive_errors = 0;
                let Some(ipv4_payload) = extract_forwardable_ipv4_payload(
                    packet,
                    local_ip,
                    &resolver_ips,
                    flag_id,
                ) else {
                    continue;
                };

                let cloned_ipv4: Arc<Vec<u8>> = Arc::new(ipv4_payload);
                match dns_send.send(cloned_ipv4) {
                    Ok(_) => {}
                    Err(error) => {
                        warn!("发送抓到的数据包失败: {}", error);
                        break;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(error) => {
                consecutive_errors += 1;
                warn!("读取数据链路通道时发生错误: {}", error);
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    warn!("连续错误次数过多，停止抓包");
                    break;
                }
            }
        }
    }

    drop(dns_send);
    drop(rx);
}

pub fn recv_udp(socket: UdpSocket, dns_send: mpsc::Sender<Arc<Vec<u8>>>, running: Arc<AtomicBool>) {
    if let Err(error) = socket.set_read_timeout(Some(Duration::from_millis(1000))) {
        error!("设置UDP兼容接收超时失败: {}", error);
        return;
    }

    let mut buffer = vec![0u8; 4096];

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => {
                if dns_send.send(Arc::new(buffer[..len].to_vec())).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                warn!("UDP兼容接收失败: {}", error);
                break;
            }
        }
    }
}

fn extract_forwardable_ipv4_payload(
    packet_data: &[u8],
    local_ip: Ipv4Addr,
    resolver_ips: &[Ipv4Addr],
    flag_id: u16,
) -> Option<Vec<u8>> {
    let Some(ethernet) = EthernetPacket::new(packet_data) else {
        return None;
    };
    let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) else {
        return None;
    };
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }
    if ipv4.get_destination() != local_ip {
        return None;
    }
    if !resolver_ips.contains(&ipv4.get_source()) {
        return None;
    }

    let Some(udp) = UdpPacket::new(ipv4.payload()) else {
        return None;
    };

    if udp.get_source() != 53 {
        return None;
    }

    let Ok(message) = Message::from_vec(udp.payload()) else {
        return None;
    };

    if message.message_type() != MessageType::Response || message.id() / 100 != flag_id {
        return None;
    }

    Some(ipv4.packet().to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::MutablePacket;

    use super::extract_forwardable_ipv4_payload;

    fn build_udp_ethernet_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        dns_message_id: u16,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 14 + 20 + 8 + 12];
        {
            let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
            ethernet.set_ethertype(EtherTypes::Ipv4);

            let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(40);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(src_ip);
            ipv4.set_destination(dst_ip);

            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length(20);
            let payload = udp.payload_mut();
            payload[0] = (dns_message_id >> 8) as u8;
            payload[1] = dns_message_id as u8;
            payload[2] = 0x81;
            payload[3] = 0x80;
        }
        buffer
    }

    #[test]
    fn forwards_only_expected_dns_response_packets() {
        let packet = build_udp_ethernet_packet(
            Ipv4Addr::new(223, 5, 5, 5),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            12000,
            41234,
        );

        assert!(extract_forwardable_ipv4_payload(
            &packet,
            Ipv4Addr::new(10, 0, 0, 2),
            &[Ipv4Addr::new(223, 5, 5, 5)],
            412
        )
        .is_some());
    }

    #[test]
    fn rejects_dns_packets_from_unexpected_source_or_port() {
        let wrong_resolver = build_udp_ethernet_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            12000,
            41234,
        );
        let wrong_port = build_udp_ethernet_packet(
            Ipv4Addr::new(223, 5, 5, 5),
            Ipv4Addr::new(10, 0, 0, 2),
            5353,
            12000,
            41234,
        );
        let wrong_flag_id = build_udp_ethernet_packet(
            Ipv4Addr::new(223, 5, 5, 5),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            12000,
            51123,
        );

        assert!(extract_forwardable_ipv4_payload(
            &wrong_resolver,
            Ipv4Addr::new(10, 0, 0, 2),
            &[Ipv4Addr::new(223, 5, 5, 5)],
            412
        )
        .is_none());
        assert!(extract_forwardable_ipv4_payload(
            &wrong_port,
            Ipv4Addr::new(10, 0, 0, 2),
            &[Ipv4Addr::new(223, 5, 5, 5)],
            412
        )
        .is_none());
        assert!(extract_forwardable_ipv4_payload(
            &wrong_flag_id,
            Ipv4Addr::new(10, 0, 0, 2),
            &[Ipv4Addr::new(223, 5, 5, 5)],
            412
        )
        .is_none());
    }
}
