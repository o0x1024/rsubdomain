use std::net::IpAddr;

use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};

pub(super) fn build_resolver_config(
    resolvers: &[String],
) -> Result<ResolverConfig, Box<dyn std::error::Error>> {
    let ips: Vec<IpAddr> = resolvers
        .iter()
        .map(|resolver| resolver.parse())
        .collect::<Result<Vec<IpAddr>, _>>()?;

    if ips.is_empty() {
        return Ok(ResolverConfig::default());
    }

    Ok(ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&ips, 53, true),
    ))
}
