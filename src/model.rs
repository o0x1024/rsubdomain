use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;

use crate::QueryType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTransport {
    Ethernet,
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
    pub time: u64,             // 发送时间
    pub retry: isize,          // 重试次数
    pub domain_level: isize,   // 域名层级
}
