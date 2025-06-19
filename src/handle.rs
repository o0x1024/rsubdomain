use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, IpAddr};
use std::fmt;

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

/// 发现的域名结果
#[derive(Debug, Clone)]
pub struct DiscoveredDomain {
    pub domain: String,
    pub ip: String,
    pub record_type: String,
    pub timestamp: u64,
}

/// 验证结果
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub domain: String,
    pub ip: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub is_alive: bool,
}

/// 汇总统计信息
#[derive(Debug, Clone)]
pub struct SummaryStats {
    pub total_domains: usize,
    pub unique_ips: HashSet<String>,
    pub ip_ranges: HashMap<String, Vec<String>>,
    pub record_types: HashMap<String, usize>,
    pub verified_domains: usize,
    pub alive_domains: usize,
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}",
            self.domain,
            self.ip,
            self.http_status.map_or("N/A".to_string(), |s| s.to_string()),
            self.https_status.map_or("N/A".to_string(), |s| s.to_string()),
            self.title.as_deref().unwrap_or("N/A"),
            if self.is_alive { "YES" } else { "NO" }
        )
    }
}

/// 全局结果收集器
lazy_static::lazy_static! {
    pub static ref DISCOVERED_DOMAINS: Arc<Mutex<Vec<DiscoveredDomain>>> = Arc::new(Mutex::new(Vec::new()));
    pub static ref VERIFICATION_RESULTS: Arc<Mutex<Vec<VerificationResult>>> = Arc::new(Mutex::new(Vec::new()));
}

pub fn handle_dns_packet(
    dns_recv: mpsc::Receiver<Arc<Vec<u8>>>,
    flag_id: u16,
    running: Arc<AtomicBool>,
    silent: bool,
) {
    // 打印表格头部
    if !silent {
        println!("\n{:<30} {:<45} {:<7} {:<20}", "域名", "IP地址", "记录类型", "时间戳");
        println!("{}", "-".repeat(110));
    }

    let mut domain_list: Vec<String> = Vec::new();
    let mut ip_list: Vec<String> = Vec::new();

    while running.load(Ordering::Relaxed) {
        match dns_recv.recv() {
            Ok(ipv4_packet) => {
                if let Some(ipv4) = Ipv4Packet::new(ipv4_packet.as_ref()) {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if let Some(dns) = DnsPacket::new(udp.payload()) {
                                process_dns_response(
                                    &dns, 
                                    flag_id, 
                                    &udp, 
                                    silent,
                                    &mut domain_list,
                                    &mut ip_list
                                );
                            }
                        }
                    }
                }
            }
            Err(_) => (),
        }
    }
}

/// 处理DNS响应
fn process_dns_response(
    dns: &DnsPacket,
    flag_id: u16,
    udp: &UdpPacket,
    silent: bool,
    domain_list: &mut Vec<String>,
    ip_list: &mut Vec<String>,
) {
    let mut query_name: String = String::new();
    if dns.get_is_response() == 0 {
        return;
    }
    
    let tid = dns.get_id() / 100;
    if tid == flag_id {
        if dns.get_response_count() > 0 {
            query_name = dns.get_queries()[0].get_qname_parsed();
            let timestamp = chrono::Utc::now().timestamp() as u64;

            for res in dns.get_responses() {
                match res.rtype {
                    DnsTypes::A => {
                        let query_name_clone = query_name.clone();
                        let ipaddr = res
                            .data
                            .iter()
                            .map(|byte| byte.to_string())
                            .collect::<Vec<String>>()
                            .join(".");
                        
                        // 添加到发现的域名列表
                        let discovered = DiscoveredDomain {
                            domain: query_name.clone(),
                            ip: ipaddr.clone(),
                            record_type: "A".to_string(),
                            timestamp,
                        };
                        
                        if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
                            domains.push(discovered);
                        }

                        if silent {
                            println!("{}", query_name);
                        } else {
                            println!("{:<30} {:<50} {:<10} {}", 
                                query_name, ipaddr, "A", 
                                chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                    .unwrap_or_default()
                                    .format("%H:%M:%S")
                            );
                        }

                        domain_list.push(query_name_clone);
                        ip_list.push(ipaddr);
                    }
                    DnsTypes::CNAME => {
                        // 修复CNAME记录解析
                        let cname_data = parse_dns_name(&res.data);
                        
                        let discovered = DiscoveredDomain {
                            domain: query_name.clone(),
                            ip: cname_data.clone(),
                            record_type: "CNAME".to_string(),
                            timestamp,
                        };
                        
                        if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
                            domains.push(discovered);
                        }

                        if !silent {
                            println!("{:<30} {:<50} {:<10} {}", 
                                query_name, cname_data, "CNAME",
                                chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                    .unwrap_or_default()
                                    .format("%H:%M:%S")
                            );
                        }
                    }
                    DnsTypes::NS => {
                        // 修复NS记录解析
                        let ns_data = parse_dns_name(&res.data);
                        
                        let discovered = DiscoveredDomain {
                            domain: query_name.clone(),
                            ip: ns_data.clone(),
                            record_type: "NS".to_string(),
                            timestamp,
                        };
                        
                        if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
                            domains.push(discovered);
                        }

                        if !silent {
                            println!("{:<30} {:<50} {:<10} {}", 
                                query_name, ns_data, "NS",
                                chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                    .unwrap_or_default()
                                    .format("%H:%M:%S")
                            );
                        }
                    }
                    DnsTypes::MX => {
                        // 修复MX记录解析
                        if res.data.len() >= 2 {
                            let priority = u16::from_be_bytes([res.data[0], res.data[1]]);
                            let mx_data = parse_dns_name(&res.data[2..]);
                            let mx_record = format!("{} {}", priority, mx_data);
                            
                            let discovered = DiscoveredDomain {
                                domain: query_name.clone(),
                                ip: mx_record.clone(),
                                record_type: "MX".to_string(),
                                timestamp,
                            };
                            
                            if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
                                domains.push(discovered);
                            }

                            if !silent {
                                println!("{:<30} {:<50} {:<10} {}", 
                                    query_name, mx_record, "MX",
                                    chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                        .unwrap_or_default()
                                        .format("%H:%M:%S")
                                );
                            }
                        }
                    }
                    DnsTypes::TXT => {
                        // 修复TXT记录解析
                        let txt_data = parse_txt_record(&res.data);
                        
                        let discovered = DiscoveredDomain {
                            domain: query_name.clone(),
                            ip: txt_data.clone(),
                            record_type: "TXT".to_string(),
                            timestamp,
                        };
                        
                        if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
                            domains.push(discovered);
                        }

                        if !silent {
                            println!("{:<30} {:<50} {:<10} {}", 
                                query_name, 
                                if txt_data.len() > 15 { 
                                    format!("{}...", &txt_data[..12]) 
                                } else { 
                                    txt_data.clone() 
                                }, 
                                "TXT",
                                chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                    .unwrap_or_default()
                                    .format("%H:%M:%S")
                            );
                        }
                    }
                    _ => (),
                }
            }
        }
        
        // 处理本地状态
        update_local_status(dns, udp);
    }
}

/// 解析DNS名称（用于CNAME、NS等记录）
fn parse_dns_name(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 {
            break;
        }
        
        // 检查是否是指针（压缩格式）
        if len & 0xC0 == 0xC0 {
            // 这是一个指针，暂时简单处理
            result.push_str("compressed");
            break;
        }
        
        if i + len + 1 > data.len() {
            break;
        }
        
        if !result.is_empty() {
            result.push('.');
        }
        
        let label = String::from_utf8_lossy(&data[i + 1..i + 1 + len]);
        result.push_str(&label);
        i += len + 1;
    }
    
    if result.is_empty() {
        result = String::from_utf8_lossy(data).to_string();
    }
    
    result
}

/// 解析TXT记录
fn parse_txt_record(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + len + 1 > data.len() {
            break;
        }
        
        let text = String::from_utf8_lossy(&data[i + 1..i + 1 + len]);
        result.push_str(&text);
        i += len + 1;
        
        if i < data.len() {
            result.push(' ');
        }
    }
    
    result
}

/// 更新本地状态
fn update_local_status(dns: &DnsPacket, udp: &UdpPacket) {
    match LOCAL_STATUS.write() {
        Ok(mut local_status) => {
            let index = send::generate_map_index(
                dns.get_id() % 100,
                udp.get_destination(),
            );
            match local_status.search_from_index_and_delete(index as u32) {
                Ok(_data) => {
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

/// 添加验证结果
pub fn add_verification_result(result: VerificationResult) {
    if let Ok(mut results) = VERIFICATION_RESULTS.lock() {
        results.push(result);
    }
}

/// 实时打印验证结果
pub fn print_verification_result(result: &VerificationResult) {
    static HEADER_PRINTED: std::sync::Once = std::sync::Once::new();
    
    HEADER_PRINTED.call_once(|| {
        println!("\n{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}", 
            "域名", "IP地址", "HTTP", "HTTPS", "标题", "存活");
        println!("{}", "-".repeat(90));
    });
    
    println!("{}", result);
}

/// 获取发现的域名列表
pub fn get_discovered_domains() -> Vec<DiscoveredDomain> {
    if let Ok(domains) = DISCOVERED_DOMAINS.lock() {
        domains.clone()
    } else {
        Vec::new()
    }
}

/// 获取验证结果列表
pub fn get_verification_results() -> Vec<VerificationResult> {
    if let Ok(results) = VERIFICATION_RESULTS.lock() {
        results.clone()
    } else {
        Vec::new()
    }
}

/// 生成汇总统计
pub fn generate_summary() -> SummaryStats {
    let discovered = get_discovered_domains();
    let verified = get_verification_results();
    
    let mut unique_ips = HashSet::new();
    let mut record_types = HashMap::new();
    let mut ip_ranges = HashMap::new();
    
    // 统计发现的域名
    for domain in &discovered {
        if let Ok(ip) = domain.ip.parse::<IpAddr>() {
            unique_ips.insert(domain.ip.clone());
            
            // 计算IP段
            if let IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                let range = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                ip_ranges.entry(range).or_insert_with(Vec::new).push(domain.ip.clone());
            }
        }
        
        *record_types.entry(domain.record_type.clone()).or_insert(0) += 1;
    }
    
    let verified_count = verified.len();
    let alive_count = verified.iter().filter(|v| v.is_alive).count();
    
    SummaryStats {
        total_domains: discovered.len(),
        unique_ips,
        ip_ranges,
        record_types,
        verified_domains: verified_count,
        alive_domains: alive_count,
    }
}

/// 打印汇总信息
pub fn print_summary() {
    let summary = generate_summary();
    
    println!("\n{}", "=".repeat(60));
    println!("                    汇总统计");
    println!("{}", "=".repeat(60));
    
    println!("发现域名总数: {}", summary.total_domains);
    println!("唯一IP数量: {}", summary.unique_ips.len());
    println!("已验证域名: {}", summary.verified_domains);
    println!("存活域名: {}", summary.alive_domains);
    
    println!("\n记录类型分布:");
    for (record_type, count) in &summary.record_types {
        println!("  {}: {}", record_type, count);
    }
    
    println!("\nIP段分布 (前10个):");
    let mut sorted_ranges: Vec<_> = summary.ip_ranges.iter().collect();
    sorted_ranges.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    
    for (range, ips) in sorted_ranges.iter().take(10) {
        println!("  {}: {} 个IP", range, ips.len());
    }
    
    if summary.unique_ips.len() > 0 {
        println!("\n发现的IP地址 (前20个):");
        let mut sorted_ips: Vec<_> = summary.unique_ips.iter().collect();
        sorted_ips.sort();
        for ip in sorted_ips.iter().take(20) {
            println!("  {}", ip);
        }
        if summary.unique_ips.len() > 20 {
            println!("  ... 还有 {} 个IP", summary.unique_ips.len() - 20);
        }
    }
    
    println!("{}", "=".repeat(60));
}

/// 清空发现的域名列表
pub fn clear_discovered_domains() {
    if let Ok(mut domains) = DISCOVERED_DOMAINS.lock() {
        domains.clear();
    }
}

/// 清空验证结果列表
pub fn clear_verification_results() {
    if let Ok(mut results) = VERIFICATION_RESULTS.lock() {
        results.clear();
    }
}
