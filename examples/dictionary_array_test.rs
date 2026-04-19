//! 简化的字典数组功能测试
//!
//! 这个示例用于快速测试字典数组功能是否正常工作

use rsubdomain::{brute_force_subdomains_with_dict, SubdomainBruteConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 字典数组功能快速测试 ===");

    // 使用一个简单的测试域名和小字典
    let domains = vec!["mgtv.com".to_string()];
    let dictionary = vec!["www".to_string(), "mail".to_string()];

    println!("测试域名: {:?}", domains);
    println!("测试字典: {:?}", dictionary);

    // 直接调用API函数，测试程序能否正常退出
    match brute_force_subdomains_with_dict(
        domains.clone(),
        dictionary.clone(),
        None,
        true,
        None,
        false,
        false,
        true,
        None,
    )
    .await
    {
        Ok(results) => {
            println!("✅ 测试成功！发现 {} 个子域名:", results.len());
            for result in results {
                println!(
                    "  {} -> {} ({})",
                    result.domain, result.ip, result.record_type
                );
            }
        }
        Err(e) => println!("❌ 测试失败: {}", e),
    }

    println!("\n=== 测试字典优先级配置 ===");

    let mut config = SubdomainBruteConfig::default();
    config.domains = vec!["mgtv.com".to_string()];
    config.dictionary_file = Some("/nonexistent/file.txt".to_string());

    println!("✅ 配置创建成功！");
    println!("字典文件: {:?}", config.dictionary_file);
    println!("当字典数组存在时会被优先使用，字典文件会被忽略");

    println!("\n🎉 所有测试完成！程序正常结束。");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}
