use std::fmt;

use super::ProgressCallback;
use crate::QueryType;

/// 域名暴破配置
#[derive(Clone)]
pub struct SubdomainBruteConfig {
    /// 目标域名列表
    pub domains: Vec<String>,
    /// DNS服务器列表
    pub resolvers: Vec<String>,
    /// 字典文件路径
    pub dictionary_file: Option<String>,
    /// 字典数组（直接传入字典数据）
    pub dictionary: Option<Vec<String>>,
    /// 是否跳过泛解析
    pub skip_wildcard: bool,
    /// 带宽限制 (如 "3M", "5K", "10G")
    pub bandwidth_limit: Option<String>,
    /// 是否启用验证模式
    pub verify_mode: bool,
    /// DNS查询超时后的最大重试次数
    pub max_retries: u8,
    /// 发包完成后的最大等待时间（秒）
    pub max_wait_seconds: u64,
    /// HTTP/HTTPS验证超时时间（秒）
    pub verify_timeout_seconds: u64,
    /// HTTP/HTTPS验证并发度
    pub verify_concurrency: usize,
    /// 是否解析DNS记录
    pub resolve_records: bool,
    /// 主动发送的DNS查询类型
    pub query_types: Vec<QueryType>,
    /// 是否静默模式
    pub silent: bool,
    /// 是否输出原始逐记录结果
    pub raw_records: bool,
    /// 网络设备名称
    pub device: Option<String>,
    /// 进度回调
    pub progress_callback: Option<ProgressCallback>,
}

impl fmt::Debug for SubdomainBruteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubdomainBruteConfig")
            .field("domains", &self.domains)
            .field("resolvers", &self.resolvers)
            .field("dictionary_file", &self.dictionary_file)
            .field("dictionary", &self.dictionary)
            .field("skip_wildcard", &self.skip_wildcard)
            .field("bandwidth_limit", &self.bandwidth_limit)
            .field("verify_mode", &self.verify_mode)
            .field("max_retries", &self.max_retries)
            .field("max_wait_seconds", &self.max_wait_seconds)
            .field("verify_timeout_seconds", &self.verify_timeout_seconds)
            .field("verify_concurrency", &self.verify_concurrency)
            .field("resolve_records", &self.resolve_records)
            .field("query_types", &self.query_types)
            .field("silent", &self.silent)
            .field("raw_records", &self.raw_records)
            .field("device", &self.device)
            .field(
                "progress_callback",
                &self.progress_callback.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl Default for SubdomainBruteConfig {
    fn default() -> Self {
        SubdomainBruteConfig {
            domains: Vec::new(),
            resolvers: Vec::new(),
            dictionary_file: None,
            dictionary: None,
            skip_wildcard: false,
            bandwidth_limit: Some("3M".to_string()),
            verify_mode: false,
            max_retries: 5,
            max_wait_seconds: 300,
            verify_timeout_seconds: 10,
            verify_concurrency: 50,
            resolve_records: false,
            query_types: vec![QueryType::A],
            silent: false,
            raw_records: false,
            device: None,
            progress_callback: None,
        }
    }
}
