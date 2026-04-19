use reqwest::Client;
use std::time::Duration;

/// HTTP验证结果
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub domain: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub http_alive: bool,
    pub https_alive: bool,
    pub redirect_url: Option<String>,
    pub server_header: Option<String>,
    pub title: Option<String>,
}

/// 域名验证器
pub struct DomainVerifier {
    pub(super) client: Client,
    pub(super) timeout_duration: Duration,
    pub(super) max_concurrency: usize,
}
