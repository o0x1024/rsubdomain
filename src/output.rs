use std::fs::File;
use std::io::Write;
use serde::{Deserialize, Serialize};
use crate::handle::{DiscoveredDomain, VerificationResult, SummaryStats};
use crate::input::OutputFormat;

/// 可序列化的发现域名结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDiscoveredDomain {
    pub domain: String,
    pub ip: String,
    pub record_type: String,
    pub timestamp: u64,
    pub formatted_time: String,
}

/// 可序列化的验证结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableVerificationResult {
    pub domain: String,
    pub ip: String,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub is_alive: bool,
}

/// 可序列化的汇总统计结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSummaryStats {
    pub total_domains: usize,
    pub unique_ips: Vec<String>,
    pub ip_ranges: std::collections::HashMap<String, Vec<String>>,
    pub record_types: std::collections::HashMap<String, usize>,
    pub verified_domains: usize,
    pub alive_domains: usize,
}

/// 完整的导出数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    pub discovered_domains: Vec<SerializableDiscoveredDomain>,
    pub verification_results: Vec<SerializableVerificationResult>,
    pub summary: SerializableSummaryStats,
    pub export_time: String,
}

impl From<DiscoveredDomain> for SerializableDiscoveredDomain {
    fn from(domain: DiscoveredDomain) -> Self {
        let formatted_time = chrono::DateTime::from_timestamp(domain.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
            
        SerializableDiscoveredDomain {
            domain: domain.domain,
            ip: domain.ip,
            record_type: domain.record_type,
            timestamp: domain.timestamp,
            formatted_time,
        }
    }
}

impl From<VerificationResult> for SerializableVerificationResult {
    fn from(result: VerificationResult) -> Self {
        SerializableVerificationResult {
            domain: result.domain,
            ip: result.ip,
            http_status: result.http_status,
            https_status: result.https_status,
            title: result.title,
            server: result.server,
            is_alive: result.is_alive,
        }
    }
}

impl From<SummaryStats> for SerializableSummaryStats {
    fn from(stats: SummaryStats) -> Self {
        SerializableSummaryStats {
            total_domains: stats.total_domains,
            unique_ips: stats.unique_ips.into_iter().collect(),
            ip_ranges: stats.ip_ranges,
            record_types: stats.record_types,
            verified_domains: stats.verified_domains,
            alive_domains: stats.alive_domains,
        }
    }
}

/// 导出结果到文件
pub fn export_results(
    discovered: Vec<DiscoveredDomain>,
    verified: Vec<VerificationResult>,
    summary: SummaryStats,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let export_data = ExportData {
        discovered_domains: discovered.into_iter().map(|d| d.into()).collect(),
        verification_results: verified.into_iter().map(|v| v.into()).collect(),
        summary: summary.into(),
        export_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    };

    let mut file = File::create(output_path)?;

    match format {
        OutputFormat::Json => {
            let json_data = serde_json::to_string_pretty(&export_data)?;
            file.write_all(json_data.as_bytes())?;
        }
        OutputFormat::Xml => {
            let xml_data = export_to_xml(&export_data)?;
            file.write_all(xml_data.as_bytes())?;
        }
        OutputFormat::Csv => {
            let csv_data = export_to_csv(&export_data)?;
            file.write_all(csv_data.as_bytes())?;
        }
        OutputFormat::Txt => {
            let txt_data = export_to_txt(&export_data)?;
            file.write_all(txt_data.as_bytes())?;
        }
    }

    println!("结果已导出到: {}", output_path);
    Ok(())
}

/// 导出为XML格式
fn export_to_xml(data: &ExportData) -> Result<String, Box<dyn std::error::Error>> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rsubdomain_results>\n");
    xml.push_str(&format!("  <export_time>{}</export_time>\n", data.export_time));
    
    // 汇总信息
    xml.push_str("  <summary>\n");
    xml.push_str(&format!("    <total_domains>{}</total_domains>\n", data.summary.total_domains));
    xml.push_str(&format!("    <unique_ips_count>{}</unique_ips_count>\n", data.summary.unique_ips.len()));
    xml.push_str(&format!("    <verified_domains>{}</verified_domains>\n", data.summary.verified_domains));
    xml.push_str(&format!("    <alive_domains>{}</alive_domains>\n", data.summary.alive_domains));
    xml.push_str("  </summary>\n");
    
    // 发现的域名
    xml.push_str("  <discovered_domains>\n");
    for domain in &data.discovered_domains {
        xml.push_str("    <domain>\n");
        xml.push_str(&format!("      <name>{}</name>\n", escape_xml(&domain.domain)));
        xml.push_str(&format!("      <ip>{}</ip>\n", escape_xml(&domain.ip)));
        xml.push_str(&format!("      <record_type>{}</record_type>\n", escape_xml(&domain.record_type)));
        xml.push_str(&format!("      <timestamp>{}</timestamp>\n", domain.timestamp));
        xml.push_str(&format!("      <formatted_time>{}</formatted_time>\n", escape_xml(&domain.formatted_time)));
        xml.push_str("    </domain>\n");
    }
    xml.push_str("  </discovered_domains>\n");
    
    // 验证结果
    xml.push_str("  <verification_results>\n");
    for result in &data.verification_results {
        xml.push_str("    <result>\n");
        xml.push_str(&format!("      <domain>{}</domain>\n", escape_xml(&result.domain)));
        xml.push_str(&format!("      <ip>{}</ip>\n", escape_xml(&result.ip)));
        xml.push_str(&format!("      <http_status>{}</http_status>\n", 
            result.http_status.map_or("N/A".to_string(), |s| s.to_string())));
        xml.push_str(&format!("      <https_status>{}</https_status>\n", 
            result.https_status.map_or("N/A".to_string(), |s| s.to_string())));
        xml.push_str(&format!("      <title>{}</title>\n", 
            escape_xml(result.title.as_deref().unwrap_or("N/A"))));
        xml.push_str(&format!("      <server>{}</server>\n", 
            escape_xml(result.server.as_deref().unwrap_or("N/A"))));
        xml.push_str(&format!("      <is_alive>{}</is_alive>\n", result.is_alive));
        xml.push_str("    </result>\n");
    }
    xml.push_str("  </verification_results>\n");
    
    xml.push_str("</rsubdomain_results>\n");
    Ok(xml)
}

/// 导出为CSV格式
fn export_to_csv(data: &ExportData) -> Result<String, Box<dyn std::error::Error>> {
    let mut csv = String::new();
    
    // 发现的域名CSV
    csv.push_str("# 发现的域名\n");
    csv.push_str("Domain,IP,RecordType,Timestamp,FormattedTime\n");
    for domain in &data.discovered_domains {
        csv.push_str(&format!("{},{},{},{},{}\n",
            escape_csv(&domain.domain),
            escape_csv(&domain.ip),
            escape_csv(&domain.record_type),
            domain.timestamp,
            escape_csv(&domain.formatted_time)
        ));
    }
    
    csv.push_str("\n# 验证结果\n");
    csv.push_str("Domain,IP,HTTPStatus,HTTPSStatus,Title,Server,IsAlive\n");
    for result in &data.verification_results {
        csv.push_str(&format!("{},{},{},{},{},{},{}\n",
            escape_csv(&result.domain),
            escape_csv(&result.ip),
            result.http_status.map_or("N/A".to_string(), |s| s.to_string()),
            result.https_status.map_or("N/A".to_string(), |s| s.to_string()),
            escape_csv(result.title.as_deref().unwrap_or("N/A")),
            escape_csv(result.server.as_deref().unwrap_or("N/A")),
            result.is_alive
        ));
    }
    
    Ok(csv)
}

/// 导出为TXT格式
fn export_to_txt(data: &ExportData) -> Result<String, Box<dyn std::error::Error>> {
    let mut txt = String::new();
    
    txt.push_str(&format!("rsubdomain 扫描结果报告\n"));
    txt.push_str(&format!("导出时间: {}\n", data.export_time));
    txt.push_str(&format!("{}\n\n", "=".repeat(60)));
    
    // 汇总信息
    txt.push_str("汇总统计:\n");
    txt.push_str(&format!("  发现域名总数: {}\n", data.summary.total_domains));
    txt.push_str(&format!("  唯一IP数量: {}\n", data.summary.unique_ips.len()));
    txt.push_str(&format!("  已验证域名: {}\n", data.summary.verified_domains));
    txt.push_str(&format!("  存活域名: {}\n", data.summary.alive_domains));
    txt.push_str("\n");
    
    // 记录类型分布
    txt.push_str("记录类型分布:\n");
    for (record_type, count) in &data.summary.record_types {
        txt.push_str(&format!("  {}: {}\n", record_type, count));
    }
    txt.push_str("\n");
    
    // 发现的域名
    txt.push_str("发现的域名:\n");
    txt.push_str(&format!("{:<30} {:<15} {:<10} {:<20}\n", "域名", "IP地址", "记录类型", "时间"));
    txt.push_str(&format!("{}\n", "-".repeat(80)));
    for domain in &data.discovered_domains {
        txt.push_str(&format!("{:<30} {:<15} {:<10} {:<20}\n",
            domain.domain,
            domain.ip,
            domain.record_type,
            domain.formatted_time
        ));
    }
    txt.push_str("\n");
    
    // 验证结果
    if !data.verification_results.is_empty() {
        txt.push_str("验证结果:\n");
        txt.push_str(&format!("{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}\n", 
            "域名", "IP地址", "HTTP", "HTTPS", "标题", "存活"));
        txt.push_str(&format!("{}\n", "-".repeat(90)));
        for result in &data.verification_results {
            txt.push_str(&format!("{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}\n",
                result.domain,
                result.ip,
                result.http_status.map_or("N/A".to_string(), |s| s.to_string()),
                result.https_status.map_or("N/A".to_string(), |s| s.to_string()),
                result.title.as_deref().unwrap_or("N/A"),
                if result.is_alive { "YES" } else { "NO" }
            ));
        }
    }
    
    Ok(txt)
}

/// XML转义
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// CSV转义
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
} 