mod display;
mod dns;
mod summary;
mod types;

pub use display::{print_aggregated_domains, print_summary_stats, print_verification_result};
pub use dns::{handle_dns_packet, handle_dns_payload};
pub use summary::generate_summary_from_data;
pub use types::{
    AggregatedDiscoveredDomain, AggregatedRecordValues, DiscoveredDomain, SummaryStats,
    VerificationResult,
};
