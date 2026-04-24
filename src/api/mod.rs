mod config;
mod convenience;
mod dictionary;
mod engine;
mod progress;
mod result;

pub use config::SubdomainBruteConfig;
#[cfg(feature = "speed-test")]
pub use convenience::run_speed_test;
pub use convenience::{
    brute_force_subdomains, brute_force_subdomains_with_config, brute_force_subdomains_with_dict,
};
pub use engine::SubdomainBruteEngine;
pub use progress::{BruteForceProgress, BruteForceProgressPhase, ProgressCallback};
pub use result::{CdnAnalysisOptions, SubdomainResult, SubdomainScanData};
