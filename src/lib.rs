//! # rsubdomain
//! 
//! 一个基于Rust实现的高性能子域名暴破工具库。
//! 
//! ## 特性
//! 
//! - 🚀 **高性能**: 基于原始套接字的异步DNS查询，支持高并发
//! - 🔍 **功能丰富**: 支持子域名发现、HTTP/HTTPS验证、DNS记录解析
//! - 📊 **多格式输出**: 支持JSON、XML、CSV、TXT四种输出格式
//! - 🌐 **智能网络**: 自动检测网络设备，支持手动指定网络接口
//! - 📈 **网速测试**: 内置DNS包发送速度测试功能
//! - 🎯 **泛解析检测**: 智能识别并处理泛解析域名
//! - ⚡ **带宽控制**: 支持带宽限制，避免网络拥塞
//! - 🔄 **智能重试**: 自动处理超时和失败的DNS查询
//! 
//! ## 快速开始
//! 
//! ### 方法1: 使用便捷函数
//! 
//! ```rust,no_run
//! use rsubdomain::brute_force_subdomains;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let domains = vec!["example.com".to_string()];
//!     let results = brute_force_subdomains(
//!         domains,
//!         None,           // dictionary_file
//!         None,           // resolvers
//!         true,           // skip_wildcard
//!         None,           // bandwidth_limit
//!         false,          // verify_mode
//!         false,          // resolve_records
//!         false,          // silent
//!         None,           // device
//!     ).await?;
//!     
//!     println!("发现 {} 个子域名", results.len());
//!     for result in results.iter().take(3) {
//!         println!("  {} -> {} ({})", result.domain, result.ip, result.record_type);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### 方法2: 使用配置引擎
//! 
//! ```rust,no_run
//! use rsubdomain::{SubdomainBruteConfig, SubdomainBruteEngine};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SubdomainBruteConfig {
//!         domains: vec!["example.com".to_string()],
//!         verify_mode: true,      // 启用HTTP/HTTPS验证
//!         resolve_records: true,  // 启用DNS记录解析
//!         bandwidth_limit: Some("5M".to_string()), // 带宽限制
//!         silent: false,
//!         ..Default::default()
//!     };
//! 
//!     let engine = SubdomainBruteEngine::new(config).await?;
//!     let results = engine.run_brute_force().await?;
//!     
//!     println!("发现 {} 个子域名", results.len());
//!     for result in results.iter().take(3) {
//!         println!("  {} -> {} ({})", result.domain, result.ip, result.record_type);
//!         if let Some(verified) = &result.verified {
//!             println!("    HTTP: {}, HTTPS: {}, HTTP存活: {}, HTTPS存活: {}", 
//!                 verified.http_status.unwrap_or(0),
//!                 verified.https_status.unwrap_or(0),
//!                 verified.http_alive,
//!                 verified.https_alive
//!             );
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## 高级功能
//! 
//! ### 带宽控制和网速测试
//! 
//! ```rust,no_run
//! use rsubdomain::{run_speed_test, brute_force_subdomains};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 网速测试（5秒）
//!     run_speed_test(5).await?;
//!     
//!     // 使用带宽限制进行子域名扫描
//!     let domains = vec!["example.com".to_string()];
//!     let results = brute_force_subdomains(
//!         domains,
//!         None,
//!         None,
//!         true,
//!         Some("3M".to_string()), // 限制带宽为3M
//!         false,
//!         false,
//!         false,
//!         None,
//!     ).await?;
//!     
//!     println!("发现 {} 个子域名", results.len());
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### 使用自定义字典
//! 
//! ```rust,no_run
//! use rsubdomain::brute_force_subdomains_with_dict;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let domains = vec!["example.com".to_string()];
//!     let dictionary = vec![
//!         "www".to_string(),
//!         "mail".to_string(),
//!         "ftp".to_string(),
//!         "api".to_string(),
//!     ];
//!     
//!     let results = brute_force_subdomains_with_dict(
//!         domains,
//!         dictionary,
//!         None,  // resolvers
//!         true,  // skip_wildcard
//!         None,  // bandwidth_limit
//!         false, // verify_mode
//!         false, // resolve_records
//!         false, // silent
//!         None,  // device
//!     ).await?;
//!     
//!     println!("使用自定义字典发现 {} 个子域名", results.len());
//!     
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// 内部模块
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
pub mod structs;
pub mod handle;
pub mod wildcard;
pub mod speed_test;
pub mod verify;
pub mod dns_resolver;
pub mod api;
pub mod output;
pub mod state;

// 重新导出主要的公共API
pub use api::{
    SubdomainBruteConfig, 
    SubdomainResult, 
    SubdomainBruteEngine,
    brute_force_subdomains,
    brute_force_subdomains_with_dict,
    brute_force_subdomains_with_config,
    run_speed_test
};

// 导出其他有用的类型
pub use wildcard::WildcardDetector;
pub use verify::{DomainVerifier, VerifyResult};
pub use dns_resolver::{DnsResolver, DnsResolveResult, DnsRecord};
pub use speed_test::{SpeedTester, BandwidthLimiter, SpeedTestResult};
pub use output::export_results;
pub use input::{OutputFormat, parse_bandwidth};
pub use handle::{DiscoveredDomain, VerificationResult, SummaryStats};

// 设备相关
pub use device::{NetworkDevice, list_network_devices, print_network_devices};

// 状态管理
pub use state::BruteForceState;