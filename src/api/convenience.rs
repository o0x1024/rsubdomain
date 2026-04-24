use crate::resolver_defaults::default_resolvers;
#[cfg(feature = "speed-test")]
use crate::speed_test::SpeedTester;
use crate::{PacketTransport, QueryType};

use super::{SubdomainBruteConfig, SubdomainBruteEngine, SubdomainResult};

fn with_default_resolvers(resolvers: Option<Vec<String>>) -> Vec<String> {
    resolvers.unwrap_or_else(default_resolvers)
}

/// 便捷的域名暴破函数（使用字典文件）
pub async fn brute_force_subdomains(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file,
        dictionary: None,
        resolvers: with_default_resolvers(resolvers),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        max_retries: 5,
        dns_timeout_seconds: 10,
        max_wait_seconds: 10,
        verify_timeout_seconds: 10,
        verify_concurrency: 50,
        resolve_records,
        cdn_detect: true,
        cdn_collapse: true,
        query_types: vec![QueryType::A],
        silent,
        raw_records: false,
        device,
        transport: PacketTransport::Ethernet,
        progress_callback: None,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 便捷的域名暴破函数（使用字典数组）
pub async fn brute_force_subdomains_with_dict(
    domains: Vec<String>,
    dictionary: Vec<String>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file: None,
        dictionary: Some(dictionary),
        resolvers: with_default_resolvers(resolvers),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        max_retries: 5,
        dns_timeout_seconds: 10,
        max_wait_seconds: 10,
        verify_timeout_seconds: 10,
        verify_concurrency: 50,
        resolve_records,
        cdn_detect: true,
        cdn_collapse: true,
        query_types: vec![QueryType::A],
        silent,
        raw_records: false,
        device,
        transport: PacketTransport::Ethernet,
        progress_callback: None,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 便捷的域名暴破函数（完整配置）
pub async fn brute_force_subdomains_with_config(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    dictionary: Option<Vec<String>>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains,
        dictionary_file,
        dictionary,
        resolvers: with_default_resolvers(resolvers),
        skip_wildcard,
        bandwidth_limit,
        verify_mode,
        max_retries: 5,
        dns_timeout_seconds: 10,
        max_wait_seconds: 10,
        verify_timeout_seconds: 10,
        verify_concurrency: 50,
        resolve_records,
        cdn_detect: true,
        cdn_collapse: true,
        query_types: vec![QueryType::A],
        silent,
        raw_records: false,
        device,
        transport: PacketTransport::Ethernet,
        progress_callback: None,
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    engine.run_brute_force().await
}

/// 网速测试函数
#[cfg(feature = "speed-test")]
pub async fn run_speed_test(duration_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    let tester = SpeedTester::new().await?;
    let result = tester.run_speed_test(duration_secs).await;
    tester.display_result(&result);
    Ok(())
}
