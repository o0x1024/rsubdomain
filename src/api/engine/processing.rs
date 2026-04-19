use log::warn;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[cfg(feature = "dns-resolver")]
use crate::dns_resolver::DnsResolveResult;
use crate::send::SendDog;
use crate::speed_test::BandwidthLimiter;
#[cfg(feature = "verify")]
use crate::verify::VerifyResult;
use crate::QueryType;

use super::SubdomainBruteEngine;
#[cfg(any(feature = "verify", feature = "dns-resolver"))]
use crate::api::SubdomainResult;

impl SubdomainBruteEngine {
    #[cfg(feature = "verify")]
    pub(super) async fn attach_verification_results(
        &self,
        results: &mut [SubdomainResult],
        discovered_domains: Vec<String>,
    ) {
        if let Some(ref verifier) = self.verifier {
            let verify_results = verifier
                .verify_domains(unique_domains(discovered_domains))
                .await;
            let verify_map: std::collections::HashMap<String, VerifyResult> = verify_results
                .into_iter()
                .map(|result| (result.domain.clone(), result))
                .collect();

            for result in results {
                if let Some(verify_result) = verify_map.get(&result.domain) {
                    result.verified = Some(verify_result.clone());
                }
            }
        }
    }

    #[cfg(feature = "dns-resolver")]
    pub(super) async fn attach_dns_records(
        &self,
        results: &mut [SubdomainResult],
        discovered_domains: Vec<String>,
    ) {
        if let Some(ref resolver) = self.dns_resolver {
            let dns_results = resolver
                .resolve_domains(unique_domains(discovered_domains))
                .await;
            let dns_map: std::collections::HashMap<String, DnsResolveResult> = dns_results
                .into_iter()
                .map(|result| (result.domain.clone(), result))
                .collect();

            for result in results {
                if let Some(dns_result) = dns_map.get(&result.domain) {
                    result.dns_records = Some(dns_result.clone());
                }
            }
        }
    }

    pub(super) async fn send_dns_queries(
        &self,
        senddog: &Arc<Mutex<SendDog>>,
        sub_domain_list: &[String],
        bandwidth_limiter: &Option<BandwidthLimiter>,
        total_queries: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        self.send_queries_from_list(sub_domain_list, senddog, bandwidth_limiter, total_queries)
            .await
    }

    pub(super) async fn send_queries_from_list(
        &self,
        sub_domain_list: &[String],
        senddog: &Arc<Mutex<SendDog>>,
        bandwidth_limiter: &Option<BandwidthLimiter>,
        total_queries: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut count = 0;
        let query_types = if self.config.query_types.is_empty() {
            vec![QueryType::A]
        } else {
            self.config.query_types.clone()
        };

        for sub in sub_domain_list {
            for domain in &self.config.domains {
                for query_type in &query_types {
                    if let Some(limiter) = bandwidth_limiter {
                        limiter.can_send(64).await;
                    }

                    let mut senddog = match senddog.lock() {
                        Ok(guard) => guard,
                        Err(error) => {
                            warn!("无法锁定 senddog: {}", error);
                            continue;
                        }
                    };

                    let final_domain = format!("{}.{}", sub, domain);
                    let dns_name = senddog.chose_dns();
                    let (flagid2, scr_port) = senddog.build_status_table(
                        &self.state,
                        final_domain.as_str(),
                        dns_name.as_str(),
                        *query_type,
                        1,
                    );
                    senddog.send(final_domain, dns_name, *query_type, scr_port, flagid2)?;
                    count += 1;
                    self.emit_query_progress(count, total_queries, Some(domain));
                }
            }
        }

        Ok(count)
    }
}

fn unique_domains(domains: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for domain in domains {
        if seen.insert(domain.clone()) {
            unique.push(domain);
        }
    }

    unique
}
