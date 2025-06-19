use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;
use std::sync::Arc;

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
    client: Client,
    timeout_duration: Duration,
}

impl DomainVerifier {
    pub fn new(timeout_secs: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true) // 接受无效证书
            .build()?;

        Ok(DomainVerifier {
            client,
            timeout_duration: Duration::from_secs(timeout_secs),
        })
    }

    /// 验证单个域名的HTTP和HTTPS服务
    pub async fn verify_domain(&self, domain: &str) -> VerifyResult {
        let mut result = VerifyResult {
            domain: domain.to_string(),
            http_status: None,
            https_status: None,
            http_alive: false,
            https_alive: false,
            redirect_url: None,
            server_header: None,
            title: None,
        };

        // 测试HTTP
        if let Ok(http_result) = self.test_http(&format!("http://{}", domain)).await {
            result.http_status = Some(http_result.status);
            result.http_alive = http_result.alive;
            if result.redirect_url.is_none() {
                result.redirect_url = http_result.redirect_url;
            }
            if result.server_header.is_none() {
                result.server_header = http_result.server_header;
            }
            if result.title.is_none() {
                result.title = http_result.title;
            }
        }

        // 测试HTTPS
        if let Ok(https_result) = self.test_http(&format!("https://{}", domain)).await {
            result.https_status = Some(https_result.status);
            result.https_alive = https_result.alive;
            if result.redirect_url.is_none() {
                result.redirect_url = https_result.redirect_url;
            }
            if result.server_header.is_none() {
                result.server_header = https_result.server_header;
            }
            if result.title.is_none() {
                result.title = https_result.title;
            }
        }

        result
    }

    /// 批量验证域名
    pub async fn verify_domains(&self, domains: Vec<String>) -> Vec<VerifyResult> {
        let mut results = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(50)); // 限制并发数

        let mut tasks = Vec::new();
        for domain in domains {
            let permit = Arc::clone(&semaphore);
            let verifier = self.clone_client();
            
            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                verifier.verify_domain(&domain).await
            });
            tasks.push(task);
        }

        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        results
    }

    /// 测试HTTP请求
    async fn test_http(&self, url: &str) -> Result<HttpTestResult, Box<dyn std::error::Error>> {
        let response = timeout(self.timeout_duration, self.client.get(url).send()).await??;
        
        let status = response.status().as_u16();
        let alive = status >= 200 && status < 400;
        
        let server_header = response
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let redirect_url = if response.status().is_redirection() {
            response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        let body = response.text().await.unwrap_or_default();
        let title = self.extract_title(&body);

        Ok(HttpTestResult {
            status,
            alive,
            redirect_url,
            server_header,
            title,
        })
    }

    /// 提取HTML标题
    fn extract_title(&self, html: &str) -> Option<String> {
        let re = regex::Regex::new(r"<title[^>]*>([^<]*)</title>").ok()?;
        re.captures(html)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// 克隆客户端用于并发
    fn clone_client(&self) -> DomainVerifier {
        DomainVerifier {
            client: self.client.clone(),
            timeout_duration: self.timeout_duration,
        }
    }

    /// 显示验证结果
    pub fn display_results(&self, results: &[VerifyResult]) {
        println!("=== 域名验证结果 ===");
        for result in results {
            if result.http_alive || result.https_alive {
                let mut status_info = Vec::new();
                
                if result.http_alive {
                    status_info.push(format!("HTTP:{}", result.http_status.unwrap_or(0)));
                }
                
                if result.https_alive {
                    status_info.push(format!("HTTPS:{}", result.https_status.unwrap_or(0)));
                }

                let mut extra_info = Vec::new();
                if let Some(ref title) = result.title {
                    extra_info.push(format!("标题: {}", title));
                }
                if let Some(ref server) = result.server_header {
                    extra_info.push(format!("服务器: {}", server));
                }
                if let Some(ref redirect) = result.redirect_url {
                    extra_info.push(format!("重定向: {}", redirect));
                }

                println!("{} [{}] {}", 
                    result.domain,
                    status_info.join(", "),
                    if extra_info.is_empty() { String::new() } else { format!("- {}", extra_info.join(", ")) }
                );
            }
        }
    }
}

#[derive(Debug)]
struct HttpTestResult {
    status: u16,
    alive: bool,
    redirect_url: Option<String>,
    server_header: Option<String>,
    title: Option<String>,
} 