pub mod logger;
pub mod device;
pub mod util;
pub mod input;
pub mod subdata;
pub mod send;
pub mod recv;
pub mod model;
pub mod stack;
pub mod local_struct;
pub mod gen;
pub mod structs ;
pub mod handle;
pub mod wildcard;
pub mod speed_test;
pub mod verify;
pub mod dns_resolver;
pub mod api;
pub mod output;

// 重新导出主要的API
pub use api::{
    SubdomainBruteConfig, 
    SubdomainResult, 
    SubdomainBruteEngine,
    brute_force_subdomains,
    run_speed_test
};
pub use wildcard::WildcardDetector;
pub use verify::{DomainVerifier, VerifyResult};
pub use dns_resolver::{DnsResolver, DnsResolveResult, DnsRecord};
pub use speed_test::{SpeedTester, BandwidthLimiter, SpeedTestResult};
pub use output::export_results;
pub use input::OutputFormat;