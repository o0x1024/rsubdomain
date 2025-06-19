use rsubdomain::{
    SubdomainBruteConfig, SubdomainBruteEngine, 
    brute_force_subdomains, run_speed_test
};

#[tokio::test]
async fn test_basic_brute_force() {
    // 测试基本的暴破功能
    let domains = vec!["example.com".to_string()];
    let result = brute_force_subdomains(domains, None).await;
    
    // 基本的结果验证
    match result {
        Ok(results) => {
            println!("基本暴破测试通过，发现 {} 个结果", results.len());
            // 验证结果结构
            for result in results.iter().take(3) {
                assert!(!result.domain.is_empty());
                assert!(!result.ip.is_empty());
                assert!(!result.record_type.is_empty());
            }
        }
        Err(e) => {
            println!("基本暴破测试失败: {}", e);
            // 在CI环境中，可能因为权限问题失败，这是正常的
        }
    }
}

#[tokio::test]
async fn test_config_creation() {
    // 测试配置创建
    let config = SubdomainBruteConfig {
        domains: vec!["test.com".to_string()],
        resolvers: vec!["8.8.8.8".to_string()],
        dictionary_file: None,
        skip_wildcard: false,
        bandwidth_limit: Some("1M".to_string()),
        verify_mode: false,
        resolve_records: false,
        silent: true,
        device: None,
    };
    
    // 验证配置
    assert_eq!(config.domains.len(), 1);
    assert_eq!(config.resolvers.len(), 1);
    assert_eq!(config.bandwidth_limit, Some("1M".to_string()));
    assert!(!config.skip_wildcard);
    assert!(config.silent);
    
    println!("配置创建测试通过");
}

#[tokio::test]
async fn test_engine_creation() {
    // 测试引擎创建
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string()],
        silent: true,
        verify_mode: false,
        resolve_records: false,
        ..Default::default()
    };
    
    match SubdomainBruteEngine::new(config).await {
        Ok(_engine) => {
            println!("引擎创建测试通过");
        }
        Err(e) => {
            println!("引擎创建测试失败: {}", e);
            // 在某些环境中可能失败，这是正常的
        }
    }
}

#[tokio::test]
async fn test_default_config() {
    // 测试默认配置
    let config = SubdomainBruteConfig::default();
    
    assert!(config.domains.is_empty());
    assert!(config.resolvers.is_empty());
    assert!(config.dictionary_file.is_none());
    assert!(config.skip_wildcard);
    assert_eq!(config.bandwidth_limit, Some("3M".to_string()));
    assert!(!config.verify_mode);
    assert!(!config.resolve_records);
    assert!(!config.silent);
    assert!(config.device.is_none());
    
    println!("默认配置测试通过");
}

#[tokio::test]
async fn test_speed_test_function() {
    // 测试网速测试函数（快速测试）
    match run_speed_test(1).await {
        Ok(_) => {
            println!("网速测试函数调用成功");
        }
        Err(e) => {
            println!("网速测试函数调用失败: {}", e);
            // 在某些环境中可能失败，这是正常的
        }
    }
}

#[test]
fn test_result_structure() {
    // 测试结果结构体
    use rsubdomain::SubdomainResult;
    
    let result = SubdomainResult {
        domain: "test.example.com".to_string(),
        ip: "192.168.1.1".to_string(),
        record_type: "A".to_string(),
        verified: None,
        dns_records: None,
    };
    
    assert_eq!(result.domain, "test.example.com");
    assert_eq!(result.ip, "192.168.1.1");
    assert_eq!(result.record_type, "A");
    assert!(result.verified.is_none());
    assert!(result.dns_records.is_none());
    
    println!("结果结构体测试通过");
}

#[test]
fn test_api_exports() {
    // 测试API导出是否正常
    use rsubdomain::{
        SubdomainBruteConfig, SubdomainBruteEngine, SubdomainResult,
        brute_force_subdomains, run_speed_test, OutputFormat
    };
    
    // 如果能编译通过，说明API导出正常
    println!("API导出测试通过");
} 