//! 带宽测试示例
//!
//! 展示如何使用公开 API 执行基础测速和自定义目标测速。

use rsubdomain::{run_speed_test, SpeedTester};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rsubdomain 带宽测试示例 ===");

    println!("\n=== 基础API测试 ===");
    let test_duration = 5;
    println!("开始进行 {} 秒的基础网速测试...", test_duration);

    match run_speed_test(test_duration).await {
        Ok(_) => println!("✅ 基础网速测试完成！"),
        Err(e) => println!("❌ 基础网速测试失败: {}", e),
    }

    println!("\n=== 自定义目标测速 ===");
    match custom_target_test("114.114.114.114", 8).await {
        Ok(_) => println!("✅ 自定义目标测速完成！"),
        Err(e) => println!("❌ 自定义目标测速失败: {}", e),
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("\n🎉 所有带宽测试完成！");

    Ok(())
}

async fn custom_target_test(
    target_ip: &str,
    duration_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let speed_tester = SpeedTester::new_with_target(target_ip).await?;
    let result = speed_tester.run_speed_test(duration_secs).await;
    speed_tester.display_result(&result);
    Ok(())
}
