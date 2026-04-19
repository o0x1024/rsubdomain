use crate::verify::{DomainVerifier, VerifyResult};

impl DomainVerifier {
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

                println!(
                    "{} [{}] {}",
                    result.domain,
                    status_info.join(", "),
                    if extra_info.is_empty() {
                        String::new()
                    } else {
                        format!("- {}", extra_info.join(", "))
                    }
                );
            }
        }
    }
}
