use rsubdomain::{brute_force_subdomains, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("rsubdomain 库使用快速入门");

    println!("\n=== 方法1: 便捷函数 ===");
    let domains = vec!["github.com".to_string()];
    match brute_force_subdomains(domains, None, None, true, None, false, false, false, None).await {
        Ok(results) => {
            println!("发现 {} 个子域名", results.len());
            for result in results.iter().take(3) {
                println!("  {} -> {}", result.domain, result.value);
            }
        }
        Err(e) => println!("暴破失败: {}", e),
    }

    println!("\n=== 方法2: 配置引擎 ===");
    let config = SubdomainBruteConfig {
        domains: vec!["github.com".to_string()],
        silent: false,
        ..Default::default()
    };

    match SubdomainBruteEngine::new(config).await {
        Ok(engine) => match engine.run_brute_force().await {
            Ok(results) => {
                println!("发现 {} 个子域名", results.len());
                for result in results.iter().take(3) {
                    println!(
                        "  {} -> {} ({})",
                        result.domain, result.value, result.record_type
                    );
                }
            }
            Err(e) => println!("暴破失败: {}", e),
        },
        Err(e) => println!("引擎创建失败: {}", e),
    }

    Ok(())
}
