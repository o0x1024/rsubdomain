//! 带宽测试示例
//! 
//! 这个示例展示如何使用 rsubdomain 库的网速测试功能
//! 测试网络带宽并显示结果，包括发包和收包统计

use rsubdomain::api::run_speed_test;
use rsubdomain::speed_test::SpeedTester;
use rsubdomain::recv;
use rsubdomain::device;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc};
use std::time::Duration;
use std::thread;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rsubdomain 带宽测试示例 ===");
    
    // 首先运行原始的API测试
    println!("\n=== 基础API测试 ===");
    let test_duration = 5;
    println!("开始进行 {} 秒的基础网速测试...", test_duration);
    
    match run_speed_test(test_duration).await {
        Ok(_) => {
            println!("✅ 基础网速测试完成！");
        }
        Err(e) => {
            println!("❌ 基础网速测试失败: {}", e);
        }
    }
    
    // 运行改进的带收包统计的测试
    println!("\n=== 改进版带宽测试（包含收包统计）===");
    match enhanced_bandwidth_test().await {
        Ok(_) => {
            println!("✅ 改进版带宽测试完成！");
        }
        Err(e) => {
            println!("❌ 改进版带宽测试失败: {}", e);
        }
    }
    
    println!("\n🎉 所有带宽测试完成！");
    
    // 给系统一些时间来清理资源
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    println!("程序正常退出...");
    
    Ok(())
}

/// 改进版带宽测试，包含收包统计功能
async fn enhanced_bandwidth_test() -> Result<(), Box<dyn std::error::Error>> {
    println!("启动改进版带宽测试，将统计发包和收包速度...");
    
    // 创建速度测试器
    let speed_tester = SpeedTester::new_with_target("114.114.114.114").await;
    
    // 获取网络设备
    let ether = device::auto_get_devices().await;
    let device_name = ether.device.clone();
    
    // 创建运行标志
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    
    // 创建通道用于接收数据包
    let (dns_sender, dns_receiver) = mpsc::channel();
    
    // 启动接收线程
    let recv_handle = thread::spawn(move || {
        recv::recv(device_name, dns_sender, running_clone);
    });
    
    // 使用Arc来共享SpeedTester
    let speed_tester = Arc::new(speed_tester);
    let speed_tester_clone = Arc::clone(&speed_tester);
    let running_for_processor = running.clone();
    
    // 启动数据包处理线程来统计收包
    let processor_handle = thread::spawn(move || {
        while running_for_processor.load(Ordering::Relaxed) {
            match dns_receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(_packet) => {
                    // 记录收到的包
                    speed_tester_clone.record_received_packet();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // 超时是正常的，继续循环
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // 发送端断开，退出
                    break;
                }
            }
        }
        println!("数据包处理线程退出");
    });
    
    // 执行网速测试
    let test_duration = 8;
    println!("开始 {} 秒的网速测试（包含收包统计）...", test_duration);
    
    let result = speed_tester.run_speed_test(test_duration).await;
    
    // 停止接收
    running.store(false, Ordering::Relaxed);
    
    // 显示结果
    speed_tester.display_result(&result);
    
    // 等待线程结束
    if let Err(e) = recv_handle.join() {
        println!("警告: 接收线程结束异常: {:?}", e);
    }
    
    if let Err(e) = processor_handle.join() {
        println!("警告: 处理线程结束异常: {:?}", e);
    }
    
    println!("改进版带宽测试完成");
    Ok(())
}

/// 展示如何在自己的代码中集成网速测试功能
#[allow(dead_code)]
async fn custom_bandwidth_test() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 自定义带宽测试集成示例 ===");
    
    // 在实际应用中，你可能需要根据网络条件调整测试时间
    let network_conditions = vec![
        ("快速测试", 2),
        ("标准测试", 5),
        ("详细测试", 10),
    ];
    
    for (test_name, duration) in network_conditions {
        println!("\n执行 {}: {} 秒", test_name, duration);
        
        let start_time = std::time::Instant::now();
        
        match run_speed_test(duration).await {
            Ok(_) => {
                let elapsed = start_time.elapsed();
                println!("✅ {} 完成，实际耗时: {:?}", test_name, elapsed);
            }
            Err(e) => {
                println!("❌ {} 失败: {}", test_name, e);
            }
        }
        
        // 测试间隔
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    
    Ok(())
}