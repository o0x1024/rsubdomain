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
//! 
//! ## 快速开始
//! 
//! ```rust,no_run
//! use rsubdomain::{brute_force_subdomains, SubdomainBruteConfig, SubdomainBruteEngine};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 基本使用
//!     let domains = vec!["example.com".to_string()];
//!     let results = brute_force_subdomains(domains, None).await?;
//!     
//!     println!("发现 {} 个子域名", results.len());
//!     for result in results.iter().take(5) {
//!         println!("  {} -> {}", result.domain, result.ip);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## 高级配置
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
//!         silent: false,
//!         ..Default::default()
//!     };
//! 
//!     let engine = SubdomainBruteEngine::new(config).await?;
//!     let results = engine.run_brute_force().await?;
//!     
//!     // 处理结果...
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

// 重新导出主要的公共API
pub use api::{
    SubdomainBruteConfig, 
    SubdomainResult, 
    SubdomainBruteEngine,
    brute_force_subdomains,
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