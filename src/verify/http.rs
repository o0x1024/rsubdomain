use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::verify::{DomainVerifier, VerifyResult};

impl DomainVerifier {
    pub fn new(
        timeout_secs: u64,
        max_concurrency: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(DomainVerifier {
            client,
            timeout_duration: Duration::from_secs(timeout_secs),
            max_concurrency,
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

        if let Ok(http_result) = self.test_http(&format!("http://{}", domain)).await {
            merge_http_result(&mut result, http_result, false);
        }

        if let Ok(https_result) = self.test_http(&format!("https://{}", domain)).await {
            merge_http_result(&mut result, https_result, true);
        }

        result
    }

    /// 批量验证域名
    pub async fn verify_domains(&self, domains: Vec<String>) -> Vec<VerifyResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrency.max(1)));
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

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }
        results
    }

    async fn test_http(&self, url: &str) -> Result<HttpTestResult, Box<dyn std::error::Error>> {
        let response = timeout(self.timeout_duration, self.client.get(url).send()).await??;

        let status = response.status().as_u16();
        let alive = status >= 200 && status < 400;

        let server_header = response
            .headers()
            .get("server")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        let redirect_url = if response.status().is_redirection() {
            response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string())
        } else {
            None
        };

        let body = response.text().await.unwrap_or_default();
        let title = extract_title(&body);

        Ok(HttpTestResult {
            status,
            alive,
            redirect_url,
            server_header,
            title,
        })
    }

    fn clone_client(&self) -> DomainVerifier {
        DomainVerifier {
            client: self.client.clone(),
            timeout_duration: self.timeout_duration,
            max_concurrency: self.max_concurrency,
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

fn merge_http_result(result: &mut VerifyResult, http_result: HttpTestResult, https: bool) {
    if https {
        result.https_status = Some(http_result.status);
        result.https_alive = http_result.alive;
    } else {
        result.http_status = Some(http_result.status);
        result.http_alive = http_result.alive;
    }

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

fn extract_title(html: &str) -> Option<String> {
    let re = regex::Regex::new(r"<title[^>]*>([^<]*)</title>").ok()?;
    re.captures(html)
        .and_then(|caps| caps.get(1))
        .map(|capture| capture.as_str().trim().to_string())
        .filter(|title| !title.is_empty())
}
