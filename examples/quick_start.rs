use rsubdomain::{brute_force_subdomains, brute_force_subdomains_with_dict, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("rsubdomain 库使用快速入门");
    
    // 方法1: 使用便捷函数（最简单）
    println!("\n=== 方法1: 便捷函数 ===");
    let domains = vec!["github.com".to_string()];
    match brute_force_subdomains(
        domains, 
        None,
        None, // resolvers
        true, // skip_wildcard
        None, // bandwidth_limit
        false, // verify_mode
        false, // resolve_records
        false, // silent
        None // device
    ).await {
        Ok(results) => {
            println!("发现 {} 个子域名", results.len());
            for result in results.iter().take(3) {
                println!("  {} -> {}", result.domain, result.ip);
            }
        }
        Err(e) => println!("暴破失败: {}", e),
    }
    
    // 方法2: 使用配置引擎（推荐）
    println!("\n=== 方法2: 配置引擎 ===");
    let config = SubdomainBruteConfig {
        domains: vec!["github.com".to_string()],
        silent: false, // 显示详细输出以便调试
        ..Default::default()
    };
    
    match SubdomainBruteEngine::new(config).await {
        Ok(engine) => {
            match engine.run_brute_force().await {
                Ok(results) => {
                    println!("发现 {} 个子域名", results.len());
                    for result in results.iter().take(3) {
                        println!("  {} -> {} ({})", result.domain, result.ip, result.record_type);
                    }
                }
                Err(e) => println!("暴破失败: {}", e),
            }
        }
        Err(e) => println!("引擎创建失败: {}", e),
    }
    
    println!("\n程序执行完成，");
    
    // 经过测试确认，程序无法自然退出，需要强制退出
    
    #[allow(unreachable_code)]
    Ok(())
}