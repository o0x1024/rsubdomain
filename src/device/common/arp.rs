use log::{info, warn};
use pnet::datalink::{self, Channel::Ethernet, Config as DatalinkConfig, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::is_valid_next_hop_mac;

const ARP_FRAME_SIZE: usize = 42;
const ARP_TIMEOUT: Duration = Duration::from_millis(400);
const ARP_ATTEMPTS: usize = 3;

pub(super) fn resolve_mac_via_arp_probe(
    interface_name: &str,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Result<MacAddr, String> {
    info!(
        "开始主动ARP探测: interface={} src_ip={} src_mac={} target_ip={}",
        interface_name, src_ip, src_mac, target_ip
    );

    let interface = find_interface(interface_name)?;
    let config = DatalinkConfig {
        read_timeout: Some(ARP_TIMEOUT),
        write_timeout: Some(ARP_TIMEOUT),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(format!(
                "接口 {} 返回了不支持的ARP数据链路通道类型",
                interface_name
            ));
        }
        Err(error) => {
            return Err(format!(
                "创建接口 {} 的ARP探测通道失败: {}",
                interface_name, error
            ));
        }
    };

    let request = build_arp_request(src_mac, src_ip, target_ip);

    for attempt in 0..ARP_ATTEMPTS {
        info!(
            "发送ARP探测请求: interface={} attempt={}/{} target_ip={}",
            interface_name,
            attempt + 1,
            ARP_ATTEMPTS,
            target_ip
        );

        match tx.send_to(&request, None) {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                return Err(format!("发送ARP探测请求失败: {}", error));
            }
            None => return Err("ARP探测缺少目标网络接口".to_string()),
        }

        let deadline = Instant::now() + ARP_TIMEOUT;
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => {
                    if let Some(mac) = parse_arp_reply(frame, target_ip, src_ip) {
                        info!(
                            "主动ARP探测成功: interface={} target_ip={} resolved_mac={}",
                            interface_name, target_ip, mac
                        );
                        return Ok(mac);
                    }

                    if let Some(summary) = summarize_arp_frame(frame) {
                        warn!(
                            "ARP探测收到未命中的ARP帧: interface={} expected_sender_ip={} expected_target_ip={} observed={}",
                            interface_name,
                            target_ip,
                            src_ip,
                            summary
                        );
                    }
                }
                Err(error) if error.kind() == ErrorKind::TimedOut => {
                    warn!(
                        "ARP探测等待响应超时: interface={} attempt={}/{} target_ip={}",
                        interface_name,
                        attempt + 1,
                        ARP_ATTEMPTS,
                        target_ip
                    );
                    break;
                }
                Err(error) => return Err(format!("接收ARP探测响应失败: {}", error)),
            }
        }
    }

    Err(format!("主动ARP探测未收到 {} 的有效响应", target_ip))
}

fn find_interface(interface_name: &str) -> Result<NetworkInterface, String> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name && !iface.is_loopback())
        .ok_or_else(|| format!("未找到ARP探测所需网络接口 {}", interface_name))
}

fn build_arp_request(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> [u8; ARP_FRAME_SIZE] {
    let mut buffer = [0u8; ARP_FRAME_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    buffer
}

fn parse_arp_reply(
    frame: &[u8],
    expected_sender_ip: Ipv4Addr,
    expected_target_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let ethernet = EthernetPacket::new(frame)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    if arp.get_sender_proto_addr() != expected_sender_ip {
        return None;
    }

    if arp.get_target_proto_addr() != expected_target_ip {
        return None;
    }

    let sender_mac = arp.get_sender_hw_addr();
    if !is_valid_next_hop_mac(sender_mac) {
        return None;
    }

    Some(sender_mac)
}

fn summarize_arp_frame(frame: &[u8]) -> Option<String> {
    let ethernet = EthernetPacket::new(frame)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    Some(format!(
        "operation={:?} sender_ip={} sender_mac={} target_ip={} target_mac={}",
        arp.get_operation(),
        arp.get_sender_proto_addr(),
        arp.get_sender_hw_addr(),
        arp.get_target_proto_addr(),
        arp.get_target_hw_addr()
    ))
}

#[cfg(test)]
mod tests {
    use super::{build_arp_request, parse_arp_reply, summarize_arp_frame, ARP_FRAME_SIZE};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::MutablePacket;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn build_arp_request_targets_broadcast() {
        let frame = build_arp_request(
            MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
        );

        let ethernet = MutableEthernetPacket::owned(frame.to_vec()).unwrap();
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);
        assert_eq!(ethernet.get_destination(), MacAddr::broadcast());
    }

    #[test]
    fn parse_arp_reply_accepts_matching_reply() {
        let mut frame = [0u8; ARP_FRAME_SIZE];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        ethernet.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        arp.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
        arp.set_target_hw_addr(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(
            parse_arp_reply(
                &frame,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2)
            ),
            Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
        );
    }

    #[test]
    fn parse_arp_reply_accepts_zero_oui_unicast_mac() {
        let mut frame = [0u8; ARP_FRAME_SIZE];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        ethernet.set_source(MacAddr::new(0, 0, 0, 0, 0, 1));
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 1));
        arp.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
        arp.set_target_hw_addr(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(
            parse_arp_reply(
                &frame,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2)
            ),
            Some(MacAddr::new(0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn summarize_arp_frame_reports_key_fields() {
        let mut frame = [0u8; ARP_FRAME_SIZE];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        arp.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
        arp.set_target_hw_addr(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 2));

        let summary = summarize_arp_frame(&frame).unwrap();

        assert!(summary.contains("sender_ip=10.0.0.1"));
        assert!(summary.contains("target_ip=10.0.0.2"));
    }
}
