use crate::model::{EthTable, PacketTransport, StatusTable};
use crate::resolver_defaults::default_resolvers;
use crate::send::SendDogError;
use crate::send::{build_dns_query, estimate_dns_query_size};
use crate::state::BruteForceState;
use crate::QueryType;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkSender};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

enum SendBackend {
    Ethernet(Arc<Mutex<Box<dyn DataLinkSender>>>),
    Udp(UdpSocket),
}

#[derive(Clone, Copy)]
struct ResolverPacketTemplate {
    destination_ip: Ipv4Addr,
    ethernet_header: [u8; 14],
}

#[derive(Clone)]
pub struct SendDog {
    ether: EthTable,
    dns: Vec<String>,
    backend: Arc<SendBackend>,
    packet_templates: Arc<Mutex<HashMap<String, ResolverPacketTemplate>>>,
    index: u16,
    lock: Arc<Mutex<()>>,
    increate_index: bool,
    flag_id: u16,
    flag_id2: u16,
}

impl SendDog {
    const UDP_IPV4_PACKET_OVERHEAD: usize = 20 + 8;
    const ETHERNET_PACKET_OVERHEAD: usize = 14 + Self::UDP_IPV4_PACKET_OVERHEAD;
    const SEND_RETRY_BACKOFFS_MS: [u64; 5] = [2, 5, 10, 20, 50];

    pub fn new(ether: EthTable, dns: Vec<String>, flag_id: u16) -> Result<SendDog, SendDogError> {
        let backend = Arc::new(match ether.transport {
            PacketTransport::Ethernet => build_ethernet_backend(&ether)?,
            PacketTransport::Udp => build_udp_backend(&ether)?,
        });

        let default_dns = if dns.is_empty() {
            default_resolvers()
        } else {
            dns
        };

        Ok(SendDog {
            ether,
            dns: default_dns,
            backend,
            packet_templates: Arc::new(Mutex::new(HashMap::new())),
            flag_id,
            index: 10000,
            lock: Arc::new(Mutex::new(())),
            increate_index: true,
            flag_id2: 0,
        })
    }

    pub fn resolvers(&self) -> &[String] {
        &self.dns
    }

    pub fn udp_receiver_socket(&self) -> Result<Option<UdpSocket>, SendDogError> {
        match self.backend.as_ref() {
            SendBackend::Ethernet(_) => Ok(None),
            SendBackend::Udp(socket) => {
                socket
                    .try_clone()
                    .map(Some)
                    .map_err(|error| SendDogError::SocketCloneFailed {
                        source: error.to_string(),
                    })
            }
        }
    }

    pub fn local_port(&self) -> Result<Option<u16>, SendDogError> {
        match self.backend.as_ref() {
            SendBackend::Ethernet(_) => Ok(None),
            SendBackend::Udp(socket) => {
                socket
                    .local_addr()
                    .map(|addr| Some(addr.port()))
                    .map_err(|error| SendDogError::SocketLocalAddressUnavailable {
                        source: error.to_string(),
                    })
            }
        }
    }

    pub fn estimate_packet_size(&self, domain: &str) -> usize {
        let dns_payload_size = estimate_dns_query_size(domain);

        match self.ether.transport {
            PacketTransport::Ethernet => dns_payload_size + Self::ETHERNET_PACKET_OVERHEAD,
            PacketTransport::Udp => dns_payload_size + Self::UDP_IPV4_PACKET_OVERHEAD,
        }
    }

    pub fn send(
        &self,
        domain: String,
        dnsname: String,
        query_type: QueryType,
        src_port: u16,
        flag_id: u16,
    ) -> Result<(), SendDogError> {
        let dns_message_id = match self.ether.transport {
            PacketTransport::Ethernet => self.flag_id * 100 + flag_id,
            PacketTransport::Udp => src_port,
        };
        let dns_query = build_dns_query(domain.as_str(), query_type, dns_message_id);
        let packet_template = self.resolve_packet_template(&dnsname)?;
        let ipv4_destination = packet_template.destination_ip;

        match self.backend.as_ref() {
            SendBackend::Ethernet(handle) => {
                if self.ether.dst_mac == pnet::util::MacAddr::zero() {
                    return Err(SendDogError::MissingDestinationMac);
                }

                let final_packet = build_ethernet_dns_packet(
                    &self.ether,
                    &packet_template,
                    src_port,
                    &dns_query,
                );
                self.send_ethernet_with_retry(handle, &final_packet)
            }
            SendBackend::Udp(socket) => self.send_udp_with_retry(
                socket,
                &dns_query,
                SocketAddrV4::new(ipv4_destination, 53),
            ),
        }
    }

    pub fn build_status_table(
        &mut self,
        state: &BruteForceState,
        domain: &str,
        dns: &str,
        query_type: QueryType,
        domain_level: isize,
        timeout_seconds: u64,
    ) -> (u16, u16) {
        let _lock = self.lock.lock().unwrap();
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
                match state.pop_from_stack() {
                    Some(value) => {
                        let (flag_id2, index) = generate_flag_index_from_map(value);
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
        let now_millis = chrono::Utc::now().timestamp_millis() as u64;
        let status = StatusTable {
            domain: domain.to_string(),
            dns: dns.to_string(),
            query_type,
            time: now_millis,
            timeout_at: now_millis + timeout_seconds.saturating_mul(1000),
            retry: 0,
            domain_level,
        };
        state.append_status(status, index as u32);
        (self.flag_id2, self.index)
    }

    fn resolve_packet_template(
        &self,
        dnsname: &str,
    ) -> Result<ResolverPacketTemplate, SendDogError> {
        if let Ok(cache) = self.packet_templates.lock() {
            if let Some(template) = cache.get(dnsname) {
                return Ok(*template);
            }
        }

        let destination_ip: Ipv4Addr =
            dnsname.parse().map_err(|error: std::net::AddrParseError| {
                SendDogError::InvalidDnsServer {
                    dns_server: dnsname.to_string(),
                    source: error.to_string(),
                }
            })?;
        let ethernet_header = build_ethernet_header(&self.ether);
        let template = ResolverPacketTemplate {
            destination_ip,
            ethernet_header,
        };

        if let Ok(mut cache) = self.packet_templates.lock() {
            cache.insert(dnsname.to_string(), template);
        }

        Ok(template)
    }

    fn send_ethernet_with_retry(
        &self,
        handle: &Arc<Mutex<Box<dyn DataLinkSender>>>,
        packet: &[u8],
    ) -> Result<(), SendDogError> {
        let mut last_error = None;

        for backoff_ms in Self::SEND_RETRY_BACKOFFS_MS.into_iter() {
            let result = {
                let mut handle = handle.lock().unwrap();
                match handle.send_to(packet, None) {
                    Some(result) => result,
                    None => return Err(SendDogError::MissingDestinationInterface),
                }
            };

            match result {
                Ok(()) => return Ok(()),
                Err(error) if is_no_buffer_space_error(&error) => {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(backoff_ms));
                }
                Err(error) => {
                    return Err(SendDogError::SendFailed {
                        source: error.to_string(),
                    });
                }
            }
        }

        Err(SendDogError::SendFailed {
            source: last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "未知发送错误".to_string()),
        })
    }

    fn send_udp_with_retry(
        &self,
        socket: &UdpSocket,
        dns_query: &[u8],
        destination: SocketAddrV4,
    ) -> Result<(), SendDogError> {
        let mut last_error = None;

        for backoff_ms in Self::SEND_RETRY_BACKOFFS_MS.into_iter() {
            match socket.send_to(dns_query, destination) {
                Ok(_) => return Ok(()),
                Err(error) if is_no_buffer_space_error(&error) => {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(backoff_ms));
                }
                Err(error) => {
                    return Err(SendDogError::SendFailed {
                        source: error.to_string(),
                    });
                }
            }
        }

        Err(SendDogError::SendFailed {
            source: last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "未知发送错误".to_string()),
        })
    }
}

fn is_no_buffer_space_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(55) | Some(105))
}

fn build_ethernet_backend(ether: &EthTable) -> Result<SendBackend, SendDogError> {
    let interfaces = datalink::interfaces();

    let interface = interfaces
        .iter()
        .find(|iface| iface.name == ether.device && !iface.is_loopback())
        .ok_or_else(|| SendDogError::InterfaceNotFound {
            device: ether.device.clone(),
        })?;

    let (tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(SendDogError::UnsupportedChannelType {
                interface: interface.name.clone(),
            });
        }
        Err(error) => {
            return Err(SendDogError::ChannelCreationFailed {
                interface: interface.name.clone(),
                source: error.to_string(),
            });
        }
    };

    Ok(SendBackend::Ethernet(Arc::new(Mutex::new(tx))))
}

fn build_udp_backend(ether: &EthTable) -> Result<SendBackend, SendDogError> {
    let socket = UdpSocket::bind(SocketAddrV4::new(ether.src_ip, 0)).map_err(|error| {
        SendDogError::SocketCreationFailed {
            source: error.to_string(),
        }
    })?;
    let _ = socket.set_write_timeout(Some(Duration::from_millis(500)));
    Ok(SendBackend::Udp(socket))
}

fn build_ethernet_dns_packet(
    ether: &EthTable,
    packet_template: &ResolverPacketTemplate,
    src_port: u16,
    dns_query: &[u8],
) -> Vec<u8> {
    let ipv4_source = ether.src_ip;
    let ipv4_destination = packet_template.destination_ip;
    let dns_query_len = dns_query.len();
    let ipv4_header_len = 20;
    let udp_header_len = 8;
    let total_length: u16 = (ipv4_header_len + udp_header_len + dns_query_len) as u16;

    let mut udp_buffer = vec![0u8; udp_header_len + dns_query_len];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(53);
    udp_header.set_length(udp_header_len as u16 + dns_query_len as u16);
    udp_header.set_payload(dns_query);

    let mut ipv4_buffer = [0u8; 20];
    let mut ipv4_header = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_header.set_header_length(69);
    ipv4_header.set_total_length(total_length);
    ipv4_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_header.set_source(ipv4_source);
    ipv4_header.set_destination(ipv4_destination);
    ipv4_header.set_identification(5636);
    ipv4_header.set_ttl(64);
    ipv4_header.set_version(4);
    ipv4_header.set_flags(Ipv4Flags::DontFragment);

    let ip_checksum = pnet::packet::ipv4::checksum(&ipv4_header.to_immutable());
    ipv4_header.set_checksum(ip_checksum);

    let udp_checksum = ipv4_checksum(&udp_header.to_immutable(), &ipv4_source, &ipv4_destination);
    udp_header.set_checksum(udp_checksum);

    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(&packet_template.ethernet_header);
    final_packet.extend_from_slice(ipv4_header.packet());
    final_packet.extend_from_slice(udp_header.packet());
    final_packet
}

fn build_ethernet_header(ether: &EthTable) -> [u8; 14] {
    let mut ethernet_buffer = [0u8; 14];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(ether.dst_mac);
    ethernet_packet.set_source(ether.src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_buffer
}

pub fn generate_map_index(flag_id2: u16, index: u16) -> i32 {
    (flag_id2 as i32 * 60000) + index as i32
}

pub fn generate_flag_index_from_map(index: usize) -> (u16, u16) {
    let threshold = 60000usize;
    let flag2 = index / threshold;
    let index2 = index % threshold;
    (flag2 as u16, index2 as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr;

    #[test]
    fn new_returns_error_for_missing_interface_instead_of_panicking() {
        let ether = EthTable {
            src_ip: Ipv4Addr::new(127, 0, 0, 1),
            device: "__rsubdomain_missing_interface__".to_string(),
            src_mac: MacAddr::new(0, 0, 0, 0, 0, 1),
            dst_mac: MacAddr::new(0, 0, 0, 0, 0, 2),
            transport: PacketTransport::Ethernet,
        };

        let result = SendDog::new(ether, Vec::new(), 1);

        assert!(matches!(
            result,
            Err(SendDogError::InterfaceNotFound { device })
            if device == "__rsubdomain_missing_interface__"
        ));
    }

    #[test]
    fn udp_transport_initializes_local_socket() {
        let ether = EthTable {
            src_ip: Ipv4Addr::new(127, 0, 0, 1),
            device: "utun-test".to_string(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            transport: PacketTransport::Udp,
        };

        let sender = SendDog::new(ether, vec!["8.8.8.8".to_string()], 1).unwrap();

        assert!(sender.local_port().unwrap().is_some());
        assert!(sender.udp_receiver_socket().unwrap().is_some());
    }

    #[test]
    fn estimate_packet_size_includes_transport_headers() {
        let domain = "www.example.com";
        let sender = SendDog::new(
            EthTable {
                src_ip: Ipv4Addr::new(127, 0, 0, 1),
                device: "utun-test".to_string(),
                src_mac: MacAddr::zero(),
                dst_mac: MacAddr::zero(),
                transport: PacketTransport::Udp,
            },
            vec!["8.8.8.8".to_string()],
            1,
        )
        .unwrap();

        assert_eq!(
            sender.estimate_packet_size(domain),
            estimate_dns_query_size(domain) + 28
        );
    }

    #[test]
    fn detects_no_buffer_space_error_by_os_code() {
        let error = io::Error::from_raw_os_error(55);

        assert!(is_no_buffer_space_error(&error));
    }
}
