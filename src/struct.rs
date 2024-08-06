use pnet::datalink::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct EthTable {
    SrcIp: Ipv4Addr,
    Device: String,
    SrcMac: MacAddr,
    DstMac: MacAddr,
}
