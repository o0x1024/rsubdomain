use crate::dns_resolver::{DnsRecord, DnsResolveResult, DnsResolver};

impl DnsResolver {
    /// 显示解析结果
    pub fn display_results(&self, results: &[DnsResolveResult]) {
        println!("=== DNS解析结果 ===");
        for result in results {
            if result.has_records {
                println!("域名: {}", result.domain);
                for (record_type, records) in &result.records {
                    println!("  {}:", record_type);
                    for record in records {
                        match record {
                            DnsRecord::A(ip) => println!("    {}", ip),
                            DnsRecord::AAAA(ip) => println!("    {}", ip),
                            DnsRecord::CNAME(cname) => println!("    {}", cname),
                            DnsRecord::NS(ns) => println!("    {}", ns),
                            DnsRecord::MX(priority, host) => println!("    {} {}", priority, host),
                            DnsRecord::TXT(txt) => println!("    \"{}\"", txt),
                            DnsRecord::SOA(soa) => println!("    {}", soa),
                            DnsRecord::PTR(ptr) => println!("    {}", ptr),
                        }
                    }
                }
                println!();
            }
        }
    }
}
