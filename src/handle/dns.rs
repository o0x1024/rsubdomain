use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, RecvTimeoutError},
    Arc,
};
use std::time::Duration;

use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
use trust_dns_resolver::proto::op::{Message, MessageType};
use trust_dns_resolver::proto::rr::RData;

use crate::handle::display::{print_discovered, print_dns_header};
use crate::handle::DiscoveredDomain;
use crate::model::StatusTable;
use crate::QueryType;
use crate::{send, state::BruteForceState};

pub fn handle_dns_packet(
    dns_recv: mpsc::Receiver<Arc<Vec<u8>>>,
    flag_id: u16,
    running: Arc<AtomicBool>,
    show_discovered_records: bool,
    state: BruteForceState,
) {
    if show_discovered_records {
        print_dns_header();
    }

    while running.load(Ordering::Relaxed) {
        match dns_recv.recv_timeout(Duration::from_millis(500)) {
            Ok(ipv4_packet) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                if let Some(ipv4) = Ipv4Packet::new(ipv4_packet.as_ref()) {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if let Ok(message) = Message::from_vec(udp.payload()) {
                                process_dns_response(
                                    &message,
                                    flag_id,
                                    udp.get_destination(),
                                    show_discovered_records,
                                    &state,
                                );
                            }
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

pub fn handle_dns_payload(
    dns_recv: mpsc::Receiver<Arc<Vec<u8>>>,
    running: Arc<AtomicBool>,
    show_discovered_records: bool,
    state: BruteForceState,
) {
    if show_discovered_records {
        print_dns_header();
    }

    while running.load(Ordering::Relaxed) {
        match dns_recv.recv_timeout(Duration::from_millis(500)) {
            Ok(payload) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                if let Ok(message) = Message::from_vec(payload.as_ref()) {
                    process_dns_response_by_message_id(&message, show_discovered_records, &state);
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn process_dns_response(
    message: &Message,
    flag_id: u16,
    destination_port: u16,
    show_discovered_records: bool,
    state: &BruteForceState,
) {
    if message.message_type() != MessageType::Response {
        return;
    }

    let tid = message.id() / 100;
    if tid == flag_id {
        let Some(request_context) = update_local_status(message.id(), destination_port, state)
        else {
            return;
        };
        record_dns_success(state, &request_context);
        if !message.answers().is_empty() {
            let query_name = request_context.domain.clone();
            let query_type = request_context.query_type;
            let timestamp = chrono::Utc::now().timestamp() as u64;

            for answer in message.answers() {
                if !is_direct_answer(&query_name, &answer.name().to_utf8()) {
                    continue;
                }
                if let Some(discovered) =
                    discovered_from_record(&query_name, query_type, answer.data(), timestamp)
                {
                    state.add_discovered_domain(discovered.clone());
                    if show_discovered_records {
                        print_discovered(&discovered);
                    }
                }
            }
        }
    }
}

fn process_dns_response_by_message_id(
    message: &Message,
    show_discovered_records: bool,
    state: &BruteForceState,
) {
    if message.message_type() != MessageType::Response {
        return;
    }

    let Some(request_context) = update_local_status_by_message_id(message.id(), state) else {
        return;
    };
    record_dns_success(state, &request_context);
    if !message.answers().is_empty() {
        let query_name = request_context.domain.clone();
        let query_type = request_context.query_type;
        let timestamp = chrono::Utc::now().timestamp() as u64;

        for answer in message.answers() {
            if !is_direct_answer(&query_name, &answer.name().to_utf8()) {
                continue;
            }
            if let Some(discovered) =
                discovered_from_record(&query_name, query_type, answer.data(), timestamp)
            {
                state.add_discovered_domain(discovered.clone());
                if show_discovered_records {
                    print_discovered(&discovered);
                }
            }
        }
    }
}

fn discovered_from_record(
    query_name: &str,
    query_type: QueryType,
    data: Option<&RData>,
    timestamp: u64,
) -> Option<DiscoveredDomain> {
    let (value, record_type) = match data? {
        RData::A(ip) => (ip.to_string(), "A".to_string()),
        RData::AAAA(ip) => (ip.to_string(), "AAAA".to_string()),
        RData::CNAME(name) => (normalize_domain(name.to_utf8()), "CNAME".to_string()),
        RData::NS(name) => (normalize_domain(name.to_utf8()), "NS".to_string()),
        RData::MX(mx) => (
            format!(
                "{} {}",
                mx.preference(),
                normalize_domain(mx.exchange().to_utf8())
            ),
            "MX".to_string(),
        ),
        RData::TXT(txt) => (
            txt.txt_data()
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
            "TXT".to_string(),
        ),
        _ => return None,
    };

    Some(DiscoveredDomain {
        domain: query_name.to_string(),
        value,
        query_type,
        record_type,
        timestamp,
    })
}

fn normalize_domain(domain: String) -> String {
    domain.trim_end_matches('.').to_string()
}

fn is_direct_answer(query_name: &str, answer_name: &str) -> bool {
    normalize_domain(query_name.to_string())
        .eq_ignore_ascii_case(&normalize_domain(answer_name.to_string()))
}

fn update_local_status(
    message_id: u16,
    destination_port: u16,
    state: &BruteForceState,
) -> Option<StatusTable> {
    let index = send::generate_map_index(message_id % 100, destination_port);
    let request_context = state
        .search_from_index_and_delete(index as u32)
        .ok()
        .map(|retry| {
            state.push_to_stack(index as usize);
            retry.v
        });
    request_context
}

fn update_local_status_by_message_id(
    message_id: u16,
    state: &BruteForceState,
) -> Option<StatusTable> {
    let request_context = state
        .search_from_index_and_delete(message_id as u32)
        .ok()
        .map(|retry| {
            state.push_to_stack(message_id as usize);
            retry.v
        });
    request_context
}

fn record_dns_success(state: &BruteForceState, request_context: &StatusTable) {
    let now_millis = chrono::Utc::now().timestamp_millis() as u64;
    let rtt_millis = now_millis.saturating_sub(request_context.time) as f64;
    state.record_resolver_success(&request_context.dns, rtt_millis);
}

#[cfg(test)]
mod tests {
    use super::{is_direct_answer, update_local_status};
    use crate::state::BruteForceState;

    #[test]
    fn direct_answer_match_ignores_trailing_dot_and_case() {
        assert!(is_direct_answer("WWW.Example.com", "www.example.com."));
    }

    #[test]
    fn direct_answer_match_rejects_cname_chain_target() {
        assert!(!is_direct_answer(
            "m.mgtv.com",
            "jxy4ydd5.sched.sma-dk.tdnsstic1.cn."
        ));
    }

    #[test]
    fn missing_request_context_does_not_recycle_stack_index() {
        let state = BruteForceState::new();

        assert!(update_local_status(1201, 10053, &state).is_none());
        assert!(state.pop_from_stack().is_none());
    }
}
