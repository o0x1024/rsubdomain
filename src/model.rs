use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;

use crate::QueryType;

#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTransport {
    #[cfg_attr(feature = "cli", value(name = "ethernet"))]
    Ethernet,
    #[cfg_attr(feature = "cli", value(name = "udp"))]
    Udp,
}

#[derive(Debug, Clone)]
pub struct EthTable {
    pub src_ip: Ipv4Addr,
    pub device: String,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub transport: PacketTransport,
}

#[derive(Clone, Debug)]
pub struct StatusTable {
    pub domain: String,        // 查询域名
    pub dns: String,           // 查询dns
    pub query_type: QueryType, // 查询类型
    pub time: u64,             // 发送时间（毫秒时间戳）
    pub timeout_at: u64,       // 超时截止时间（毫秒时间戳）
    pub retry: isize,          // 重试次数
    pub domain_level: isize,   // 域名层级
}
