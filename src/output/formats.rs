use crate::output::model::ExportData;

pub(super) fn render_xml(data: &ExportData) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rsubdomain_results>\n");
    xml.push_str(&format!(
        "  <export_time>{}</export_time>\n",
        data.export_time
    ));

    xml.push_str("  <summary>\n");
    xml.push_str(&format!(
        "    <total_domains>{}</total_domains>\n",
        data.summary.total_domains
    ));
    xml.push_str(&format!(
        "    <unique_domains>{}</unique_domains>\n",
        data.summary.unique_domains
    ));
    xml.push_str(&format!(
        "    <unique_ips_count>{}</unique_ips_count>\n",
        data.summary.unique_ips.len()
    ));
    xml.push_str(&format!(
        "    <verified_domains>{}</verified_domains>\n",
        data.summary.verified_domains
    ));
    xml.push_str(&format!(
        "    <alive_domains>{}</alive_domains>\n",
        data.summary.alive_domains
    ));
    xml.push_str("  </summary>\n");

    xml.push_str("  <discovered_domains>\n");
    for domain in &data.discovered_domains {
        xml.push_str("    <domain>\n");
        xml.push_str(&format!(
            "      <name>{}</name>\n",
            escape_xml(&domain.domain)
        ));
        xml.push_str(&format!("      <ip>{}</ip>\n", escape_xml(&domain.ip)));
        xml.push_str(&format!(
            "      <query_type>{}</query_type>\n",
            escape_xml(&domain.query_type)
        ));
        xml.push_str(&format!(
            "      <record_type>{}</record_type>\n",
            escape_xml(&domain.record_type)
        ));
        xml.push_str(&format!(
            "      <timestamp>{}</timestamp>\n",
            domain.timestamp
        ));
        xml.push_str(&format!(
            "      <formatted_time>{}</formatted_time>\n",
            escape_xml(&domain.formatted_time)
        ));
        xml.push_str("    </domain>\n");
    }
    xml.push_str("  </discovered_domains>\n");

    xml.push_str("  <verification_results>\n");
    for result in &data.verification_results {
        xml.push_str("    <result>\n");
        xml.push_str(&format!(
            "      <domain>{}</domain>\n",
            escape_xml(&result.domain)
        ));
        xml.push_str(&format!("      <ip>{}</ip>\n", escape_xml(&result.ip)));
        xml.push_str(&format!(
            "      <http_status>{}</http_status>\n",
            result
                .http_status
                .map_or("N/A".to_string(), |status| status.to_string())
        ));
        xml.push_str(&format!(
            "      <https_status>{}</https_status>\n",
            result
                .https_status
                .map_or("N/A".to_string(), |status| status.to_string())
        ));
        xml.push_str(&format!(
            "      <title>{}</title>\n",
            escape_xml(result.title.as_deref().unwrap_or("N/A"))
        ));
        xml.push_str(&format!(
            "      <server>{}</server>\n",
            escape_xml(result.server.as_deref().unwrap_or("N/A"))
        ));
        xml.push_str(&format!("      <is_alive>{}</is_alive>\n", result.is_alive));
        xml.push_str("    </result>\n");
    }
    xml.push_str("  </verification_results>\n");

    xml.push_str("</rsubdomain_results>\n");
    xml
}

pub(super) fn render_csv(data: &ExportData) -> String {
    let mut csv = String::new();

    csv.push_str("# 发现的域名\n");
    csv.push_str("Domain,IP,QueryType,RecordType,Timestamp,FormattedTime\n");
    for domain in &data.discovered_domains {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            escape_csv(&domain.domain),
            escape_csv(&domain.ip),
            escape_csv(&domain.query_type),
            escape_csv(&domain.record_type),
            domain.timestamp,
            escape_csv(&domain.formatted_time)
        ));
    }

    csv.push_str("\n# 验证结果\n");
    csv.push_str("Domain,IP,HTTPStatus,HTTPSStatus,Title,Server,IsAlive\n");
    for result in &data.verification_results {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            escape_csv(&result.domain),
            escape_csv(&result.ip),
            result
                .http_status
                .map_or("N/A".to_string(), |status| status.to_string()),
            result
                .https_status
                .map_or("N/A".to_string(), |status| status.to_string()),
            escape_csv(result.title.as_deref().unwrap_or("N/A")),
            escape_csv(result.server.as_deref().unwrap_or("N/A")),
            result.is_alive
        ));
    }

    csv
}

pub(super) fn render_txt(data: &ExportData) -> String {
    let mut txt = String::new();

    txt.push_str("rsubdomain 扫描结果报告\n");
    txt.push_str(&format!("导出时间: {}\n", data.export_time));
    txt.push_str(&format!("{}\n\n", "=".repeat(60)));

    txt.push_str("汇总统计:\n");
    txt.push_str(&format!("  发现记录总数: {}\n", data.summary.total_domains));
    txt.push_str(&format!(
        "  唯一域名数量: {}\n",
        data.summary.unique_domains
    ));
    txt.push_str(&format!(
        "  唯一IP数量: {}\n",
        data.summary.unique_ips.len()
    ));
    txt.push_str(&format!(
        "  已验证域名: {}\n",
        data.summary.verified_domains
    ));
    txt.push_str(&format!("  存活域名: {}\n", data.summary.alive_domains));
    txt.push('\n');

    txt.push_str("记录类型分布:\n");
    for (record_type, count) in &data.summary.record_types {
        txt.push_str(&format!("  {}: {}\n", record_type, count));
    }
    txt.push('\n');

    txt.push_str("发现的域名:\n");
    txt.push_str(&format!(
        "{:<30} {:<8} {:<15} {:<10} {:<20}\n",
        "域名", "查询", "IP地址", "记录类型", "时间"
    ));
    txt.push_str(&format!("{}\n", "-".repeat(90)));
    for domain in &data.discovered_domains {
        txt.push_str(&format!(
            "{:<30} {:<8} {:<15} {:<10} {:<20}\n",
            domain.domain, domain.query_type, domain.ip, domain.record_type, domain.formatted_time
        ));
    }
    txt.push('\n');

    if !data.verification_results.is_empty() {
        txt.push_str("验证结果:\n");
        txt.push_str(&format!(
            "{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}\n",
            "域名", "IP地址", "HTTP", "HTTPS", "标题", "存活"
        ));
        txt.push_str(&format!("{}\n", "-".repeat(90)));
        for result in &data.verification_results {
            txt.push_str(&format!(
                "{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}\n",
                result.domain,
                result.ip,
                result
                    .http_status
                    .map_or("N/A".to_string(), |status| status.to_string()),
                result
                    .https_status
                    .map_or("N/A".to_string(), |status| status.to_string()),
                result.title.as_deref().unwrap_or("N/A"),
                if result.is_alive { "YES" } else { "NO" }
            ));
        }
    }

    txt
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
