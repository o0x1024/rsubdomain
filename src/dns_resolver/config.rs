use crate::resolver_defaults::default_resolvers;
use std::net::IpAddr;

use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};

pub(super) fn build_resolver_config(
    resolvers: &[String],
) -> Result<ResolverConfig, Box<dyn std::error::Error>> {
    let resolver_list = if resolvers.is_empty() {
        default_resolvers()
    } else {
        resolvers.to_vec()
    };

    let ips: Vec<IpAddr> = resolver_list
        .iter()
        .map(|resolver| resolver.parse())
        .collect::<Result<Vec<IpAddr>, _>>()?;

    Ok(ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&ips, 53, true),
    ))
}
