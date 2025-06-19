use rsubdomain::{
    SubdomainBruteConfig, SubdomainBruteEngine, SubdomainResult,
    brute_force_subdomains, run_speed_test, OutputFormat, export_results
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 示例1: 使用便捷函数进行基本暴破
    println!("=== 示例1: 基本域名暴破 ===");
    basic_brute_force().await?;

    // 示例2: 使用配置引擎进行高级暴破
    println!("\n=== 示例2: 高级域名暴破 ===");
    advanced_brute_force().await?;

    // 示例3: 带验证的完整暴破
    println!("\n=== 示例3: 完整功能暴破 ===");
    full_featured_brute_force().await?;

    // 示例4: 网速测试
    println!("\n=== 示例4: 网速测试 ===");
    speed_test_example().await?;

    Ok(())
}

/// 示例1: 基本域名暴破
async fn basic_brute_force() -> Result<(), Box<dyn Error>> {
    let domains = vec!["example.com".to_string()];
    let dictionary_file = None; // 使用内置字典
    
    match brute_force_subdomains(domains, dictionary_file).await {
        Ok(results) => {
            println!("发现 {} 个子域名:", results.len());
            for result in results.iter().take(10) { // 只显示前10个
                println!("  {} -> {} ({})", result.domain, result.ip, result.record_type);
            }
        }
        Err(e) => println!("暴破失败: {}", e),
    }
    
    Ok(())
}

/// 示例2: 高级域名暴破
async fn advanced_brute_force() -> Result<(), Box<dyn Error>> {
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string(), "test.com".to_string()],
        resolvers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        dictionary_file: Some("wordlist.txt".to_string()), // 使用自定义字典
        skip_wildcard: true,
        bandwidth_limit: Some("5M".to_string()),
        verify_mode: false,
        resolve_records: false,
        silent: false,
        device: None, // 自动检测网络设备
    };

    match SubdomainBruteEngine::new(config).await {
        Ok(engine) => {
            match engine.run_brute_force().await {
                Ok(results) => {
                    println!("高级暴破发现 {} 个子域名:", results.len());
                    for result in results.iter().take(5) {
                        println!("  {} -> {} ({})", result.domain, result.ip, result.record_type);
                    }
                }
                Err(e) => println!("高级暴破失败: {}", e),
            }
        }
        Err(e) => println!("引擎创建失败: {}", e),
    }
    
    Ok(())
}

/// 示例3: 带验证的完整暴破
async fn full_featured_brute_force() -> Result<(), Box<dyn Error>> {
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string()],
        resolvers: vec!["8.8.8.8".to_string()],
        dictionary_file: None,
        skip_wildcard: true,
        bandwidth_limit: Some("3M".to_string()),
        verify_mode: true,      // 启用HTTP/HTTPS验证
        resolve_records: true,  // 启用DNS记录解析
        silent: false,
        device: Some("eth0".to_string()), // 指定网络设备
    };

    match SubdomainBruteEngine::new(config).await {
        Ok(engine) => {
            match engine.run_brute_force().await {
                Ok(results) => {
                    println!("完整暴破发现 {} 个子域名:", results.len());
                    
                    // 显示验证结果
                    for result in results.iter().take(3) {
                        println!("域名: {}", result.domain);
                        println!("  IP: {}", result.ip);
                        println!("  记录类型: {}", result.record_type);
                        
                        if let Some(ref verified) = result.verified {
                            println!("  HTTP状态: {:?}", verified.http_status);
                            println!("  HTTPS状态: {:?}", verified.https_status);
                            println!("  标题: {:?}", verified.title);
                        }
                        
                        if let Some(ref dns_records) = result.dns_records {
                            println!("  DNS记录: {:?}", dns_records.records.len());
                        }
                        
                        println!();
                    }

                    // 导出结果
                    export_results_example(&results).await?;
                }
                Err(e) => println!("完整暴破失败: {}", e),
            }
        }
        Err(e) => println!("引擎创建失败: {}", e),
    }
    
    Ok(())
}

/// 示例4: 网速测试
async fn speed_test_example() -> Result<(), Box<dyn Error>> {
    println!("执行10秒网速测试...");
    run_speed_test(10).await?;
    Ok(())
}

/// 导出结果示例
async fn export_results_example(results: &[SubdomainResult]) -> Result<(), Box<dyn Error>> {
    // 准备导出数据
    let discovered_domains: Vec<rsubdomain::handle::DiscoveredDomain> = results.iter().map(|r| {
        rsubdomain::handle::DiscoveredDomain {
            domain: r.domain.clone(),
            ip: r.ip.clone(),
            record_type: r.record_type.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }).collect();

    let verification_results: Vec<rsubdomain::handle::VerificationResult> = results.iter()
        .filter_map(|r| {
            r.verified.as_ref().map(|v| rsubdomain::handle::VerificationResult {
                domain: r.domain.clone(),
                ip: r.ip.clone(),
                http_status: v.http_status,
                https_status: v.https_status,
                title: v.title.clone(),
                server: v.server_header.clone(),
                is_alive: v.http_alive || v.https_alive,
            })
        })
        .collect();

    let summary = rsubdomain::handle::SummaryStats {
        total_domains: results.len(),
        unique_ips: results.iter().map(|r| r.ip.clone()).collect(),
        ip_ranges: std::collections::HashMap::new(),
        record_types: results.iter().fold(std::collections::HashMap::new(), |mut acc, r| {
            *acc.entry(r.record_type.clone()).or_insert(0) += 1;
            acc
        }),
        verified_domains: verification_results.len(),
        alive_domains: verification_results.iter().filter(|v| v.is_alive).count(),
    };

    // 导出为不同格式
    export_results(
        discovered_domains.clone(),
        verification_results.clone(),
        summary.clone(),
        "results.json",
        &OutputFormat::Json,
    )?;

    export_results(
        discovered_domains.clone(),
        verification_results.clone(),
        summary.clone(),
        "results.csv",
        &OutputFormat::Csv,
    )?;

    println!("结果已导出到 results.json 和 results.csv");
    Ok(())
}

/// 自定义结果处理示例
fn process_results_custom(results: &[SubdomainResult]) {
    println!("=== 自定义结果处理 ===");
    
    // 按记录类型分组
    let mut by_type: std::collections::HashMap<String, Vec<&SubdomainResult>> = 
        std::collections::HashMap::new();
    
    for result in results {
        by_type.entry(result.record_type.clone()).or_default().push(result);
    }
    
    for (record_type, domains) in by_type {
        println!("{} 记录 ({} 个):", record_type, domains.len());
        for domain in domains.iter().take(3) {
            println!("  {} -> {}", domain.domain, domain.ip);
        }
        if domains.len() > 3 {
            println!("  ... 还有 {} 个", domains.len() - 3);
        }
        println!();
    }
    
    // 统计存活的域名
    let alive_count = results.iter()
        .filter(|r| r.verified.as_ref().map_or(false, |v| v.http_alive || v.https_alive))
        .count();
    
    println!("存活域名: {} / {}", alive_count, results.len());
}

/// 错误处理示例
async fn error_handling_example() -> Result<(), Box<dyn Error>> {
    let config = SubdomainBruteConfig {
        domains: vec!["nonexistent-domain-12345.com".to_string()],
        resolvers: vec!["invalid.dns.server".to_string()],
        dictionary_file: Some("nonexistent_file.txt".to_string()),
        ..Default::default()
    };

    match SubdomainBruteEngine::new(config).await {
        Ok(engine) => {
            match engine.run_brute_force().await {
                Ok(results) => {
                    println!("意外成功: {} 个结果", results.len());
                }
                Err(e) => {
                    println!("预期的暴破错误: {}", e);
                    // 在实际应用中，这里可以进行错误恢复或重试
                }
            }
        }
        Err(e) => {
            println!("预期的引擎创建错误: {}", e);
            // 在实际应用中，这里可以使用默认配置或提示用户修正
        }
    }
    
    Ok(())
} 