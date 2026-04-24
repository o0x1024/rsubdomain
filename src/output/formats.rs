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
        "    <cdn_domains>{}</cdn_domains>\n",
        data.summary.cdn_domains
    ));
    xml.push_str(&format!(
        "    <suspected_cdn_domains>{}</suspected_cdn_domains>\n",
        data.summary.suspected_cdn_domains
    ));
    xml.push_str(&format!(
        "    <alive_domains>{}</alive_domains>\n",
        data.summary.alive_domains
    ));
    if !data.summary.cdn_providers.is_empty() {
        xml.push_str("    <cdn_providers>\n");
        for (provider, count) in &data.summary.cdn_providers {
            xml.push_str("      <provider>\n");
            xml.push_str(&format!("        <name>{}</name>\n", escape_xml(provider)));
            xml.push_str(&format!("        <count>{}</count>\n", count));
            xml.push_str("      </provider>\n");
        }
        xml.push_str("    </cdn_providers>\n");
    }
    if !data.summary.cdn_confidence.is_empty() {
        xml.push_str("    <cdn_confidence>\n");
        for (level, count) in &data.summary.cdn_confidence {
            xml.push_str("      <level>\n");
            xml.push_str(&format!("        <name>{}</name>\n", escape_xml(level)));
            xml.push_str(&format!("        <count>{}</count>\n", count));
            xml.push_str("      </level>\n");
        }
        xml.push_str("    </cdn_confidence>\n");
    }
    xml.push_str("  </summary>\n");

    xml.push_str("  <discovered_domains>\n");
    for domain in &data.discovered_domains {
        xml.push_str("    <domain>\n");
        xml.push_str(&format!(
            "      <name>{}</name>\n",
            escape_xml(&domain.domain)
        ));
        xml.push_str(&format!(
            "      <value>{}</value>\n",
            escape_xml(&domain.value)
        ));
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

    xml.push_str("  <aggregated_domains>\n");
    for domain in &data.aggregated_domains {
        xml.push_str("    <domain>\n");
        xml.push_str(&format!(
            "      <name>{}</name>\n",
            escape_xml(&domain.domain)
        ));
        xml.push_str(&format!("      <has_cdn>{}</has_cdn>\n", domain.has_cdn));
        xml.push_str(&format!(
            "      <possible_cdn>{}</possible_cdn>\n",
            domain.possible_cdn
        ));
        if let Some(provider) = &domain.cdn_provider {
            xml.push_str(&format!(
                "      <cdn_provider>{}</cdn_provider>\n",
                escape_xml(provider)
            ));
        }
        if let Some(confidence) = &domain.cdn_confidence {
            xml.push_str(&format!(
                "      <cdn_confidence>{}</cdn_confidence>\n",
                escape_xml(confidence)
            ));
        }
        xml.push_str(&format!(
            "      <raw_record_count>{}</raw_record_count>\n",
            domain.raw_record_count
        ));
        if !domain.cdn_evidence.is_empty() {
            xml.push_str("      <cdn_evidence>\n");
            for evidence in &domain.cdn_evidence {
                xml.push_str("        <evidence>\n");
                xml.push_str(&format!(
                    "          <source>{}</source>\n",
                    escape_xml(&evidence.source)
                ));
                xml.push_str(&format!(
                    "          <value>{}</value>\n",
                    escape_xml(&evidence.value)
                ));
                xml.push_str(&format!(
                    "          <detail>{}</detail>\n",
                    escape_xml(&evidence.detail)
                ));
                xml.push_str("        </evidence>\n");
            }
            xml.push_str("      </cdn_evidence>\n");
        }
        if !domain.cdn_signals.is_empty() {
            xml.push_str("      <cdn_signals>\n");
            for signal in &domain.cdn_signals {
                xml.push_str("        <signal>\n");
                xml.push_str(&format!(
                    "          <source>{}</source>\n",
                    escape_xml(&signal.source)
                ));
                xml.push_str(&format!(
                    "          <value>{}</value>\n",
                    escape_xml(&signal.value)
                ));
                xml.push_str(&format!(
                    "          <detail>{}</detail>\n",
                    escape_xml(&signal.detail)
                ));
                xml.push_str("        </signal>\n");
            }
            xml.push_str("      </cdn_signals>\n");
        }
        xml.push_str("      <records>\n");
        for record in &domain.records {
            xml.push_str("        <record>\n");
            xml.push_str(&format!(
                "          <record_type>{}</record_type>\n",
                escape_xml(&record.record_type)
            ));
            xml.push_str("          <values>\n");
            for value in &record.values {
                xml.push_str(&format!(
                    "            <value>{}</value>\n",
                    escape_xml(value)
                ));
            }
            xml.push_str("          </values>\n");
            xml.push_str("        </record>\n");
        }
        xml.push_str("      </records>\n");
        xml.push_str("    </domain>\n");
    }
    xml.push_str("  </aggregated_domains>\n");

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
    csv.push_str("Domain,Value,QueryType,RecordType,Timestamp,FormattedTime\n");
    for domain in &data.discovered_domains {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            escape_csv(&domain.domain),
            escape_csv(&domain.value),
            escape_csv(&domain.query_type),
            escape_csv(&domain.record_type),
            domain.timestamp,
            escape_csv(&domain.formatted_time)
        ));
    }

    csv.push_str("\n# 聚合域名视图\n");
    csv.push_str("Domain,Tag,CdnConfidence,CdnEvidence,CdnSignals,RecordType,Values,RawRecordCount,FirstSeen,LastSeen\n");
    for domain in &data.aggregated_domains {
        for record in &domain.records {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                escape_csv(&domain.domain),
                escape_csv(&format_cdn_label(
                    domain.has_cdn,
                    domain.possible_cdn,
                    domain.cdn_provider.as_deref(),
                    domain.cdn_confidence.as_deref(),
                )),
                escape_csv(domain.cdn_confidence.as_deref().unwrap_or("-")),
                escape_csv(&join_cdn_evidence(&domain.cdn_evidence)),
                escape_csv(&join_cdn_evidence(&domain.cdn_signals)),
                escape_csv(&record.record_type),
                escape_csv(&record.values.join(" | ")),
                domain.raw_record_count,
                domain.first_seen,
                domain.last_seen
            ));
        }
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
    txt.push_str(&format!("  CDN域名数量: {}\n", data.summary.cdn_domains));
    txt.push_str(&format!(
        "  疑似CDN域名数量: {}\n",
        data.summary.suspected_cdn_domains
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

    if !data.summary.cdn_providers.is_empty() {
        txt.push_str("CDN提供商分布:\n");
        for (provider, count) in &data.summary.cdn_providers {
            txt.push_str(&format!("  {}: {}\n", provider, count));
        }
        txt.push('\n');
    }

    if !data.summary.cdn_confidence.is_empty() {
        txt.push_str("CDN置信度分布:\n");
        for (confidence, count) in &data.summary.cdn_confidence {
            txt.push_str(&format!("  {}: {}\n", confidence, count));
        }
        txt.push('\n');
    }

    txt.push_str("发现的域名:\n");
    txt.push_str(&format!(
        "{:<30} {:<8} {:<15} {:<10} {:<20}\n",
        "域名", "查询", "记录值", "记录类型", "时间"
    ));
    txt.push_str(&format!("{}\n", "-".repeat(90)));
    for domain in &data.discovered_domains {
        txt.push_str(&format!(
            "{:<30} {:<8} {:<15} {:<10} {:<20}\n",
            domain.domain,
            domain.query_type,
            domain.value,
            domain.record_type,
            domain.formatted_time
        ));
    }
    txt.push('\n');

    if !data.aggregated_domains.is_empty() {
        txt.push_str("聚合域名视图:\n");
        txt.push_str(&format!(
            "{:<30} {:<22} {:<18} {:<52} {:<8}\n",
            "域名", "标签", "记录分布", "解析值", "原始数"
        ));
        txt.push_str(&format!("{}\n", "-".repeat(140)));
        for domain in &data.aggregated_domains {
            let record_summary = domain
                .records
                .iter()
                .map(|record| format!("{}({})", record.record_type, record.values.len()))
                .collect::<Vec<_>>()
                .join(", ");
            let value_summary = domain
                .records
                .iter()
                .map(|record| format!("{}: {}", record.record_type, record.values.join(", ")))
                .collect::<Vec<_>>()
                .join(" | ");

            txt.push_str(&format!(
                "{:<30} {:<22} {:<18} {:<52} {:<8}\n",
                domain.domain,
                truncate_text(
                    &format_cdn_label(
                        domain.has_cdn,
                        domain.possible_cdn,
                        domain.cdn_provider.as_deref(),
                        domain.cdn_confidence.as_deref(),
                    ),
                    22
                ),
                truncate_text(&record_summary, 18),
                truncate_text(&value_summary, 52),
                domain.raw_record_count
            ));
            if !domain.cdn_evidence.is_empty() {
                txt.push_str(&format!(
                    "{:<30} {:<22} {}\n",
                    "",
                    "evidence",
                    truncate_text(&join_cdn_evidence(&domain.cdn_evidence), 80)
                ));
            }
            if !domain.cdn_signals.is_empty() {
                txt.push_str(&format!(
                    "{:<30} {:<22} {}\n",
                    "",
                    "signals",
                    truncate_text(&join_cdn_evidence(&domain.cdn_signals), 80)
                ));
            }
        }
        txt.push('\n');
    }

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

fn format_cdn_label(
    has_cdn: bool,
    possible_cdn: bool,
    provider: Option<&str>,
    confidence: Option<&str>,
) -> String {
    if has_cdn {
        return match (provider, confidence) {
            (Some(provider), Some(confidence)) => format!("CDN({}): {}", confidence, provider),
            (Some(provider), None) => format!("CDN: {}", provider),
            (None, Some(confidence)) => format!("CDN({})", confidence),
            (None, None) => "CDN".to_string(),
        };
    }

    if possible_cdn {
        return "Possible CDN".to_string();
    }

    "-".to_string()
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }

    let truncated = value.chars().take(max_chars).collect::<String>();
    format!("{}...", truncated)
}

fn join_cdn_evidence(evidence: &[crate::output::model::SerializableCdnEvidence]) -> String {
    evidence
        .iter()
        .map(|item| format!("{}:{} ({})", item.source, item.value, item.detail))
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::output::model::{
        ExportData, SerializableAggregatedDiscoveredDomain, SerializableAggregatedRecordValues,
        SerializableCdnEvidence, SerializableSummaryStats,
    };

    use super::{render_csv, render_txt, render_xml};

    fn sample_export_data() -> ExportData {
        ExportData {
            raw_results: Vec::new(),
            discovered_domains: Vec::new(),
            aggregated_domains: vec![SerializableAggregatedDiscoveredDomain {
                domain: "cdn.example.com".to_string(),
                records: vec![SerializableAggregatedRecordValues {
                    record_type: "A".to_string(),
                    values: vec!["104.16.0.1".to_string()],
                }],
                has_cdn: true,
                possible_cdn: false,
                cdn_provider: Some("Cloudflare".to_string()),
                cdn_confidence: Some("high".to_string()),
                cdn_evidence: vec![SerializableCdnEvidence {
                    source: "PTR".to_string(),
                    value: "edge-1.example.cloudflare.net".to_string(),
                    detail: "suffix match cloudflare.net".to_string(),
                }],
                cdn_signals: Vec::new(),
                raw_record_count: 3,
                first_seen: 1,
                last_seen: 2,
            }],
            verification_results: Vec::new(),
            summary: SerializableSummaryStats {
                total_domains: 0,
                unique_domains: 0,
                unique_ips: Vec::new(),
                ip_ranges: HashMap::new(),
                record_types: HashMap::new(),
                cdn_domains: 1,
                suspected_cdn_domains: 0,
                cdn_providers: HashMap::from([("Cloudflare".to_string(), 1)]),
                cdn_confidence: HashMap::from([("high".to_string(), 1)]),
                verified_domains: 0,
                alive_domains: 0,
            },
            export_time: "2026-04-24 00:00:00 UTC".to_string(),
        }
    }

    #[test]
    fn render_txt_includes_aggregated_cdn_label() {
        let rendered = render_txt(&sample_export_data());
        assert!(rendered.contains("聚合域名视图"));
        assert!(rendered.contains("CDN(high): Cloudflare"));
        assert!(rendered.contains("A: 104.16.0.1"));
        assert!(rendered.contains("PTR:edge-1.example.cloudflare.net"));
    }

    #[test]
    fn render_csv_includes_aggregated_cdn_label() {
        let rendered = render_csv(&sample_export_data());
        assert!(rendered.contains("# 聚合域名视图"));
        assert!(rendered.contains("cdn.example.com,CDN(high): Cloudflare,high"));
    }

    #[test]
    fn render_xml_includes_aggregated_cdn_label() {
        let rendered = render_xml(&sample_export_data());
        assert!(rendered.contains("<aggregated_domains>"));
        assert!(rendered.contains("<has_cdn>true</has_cdn>"));
        assert!(rendered.contains("<possible_cdn>false</possible_cdn>"));
        assert!(rendered.contains("<cdn_provider>Cloudflare</cdn_provider>"));
        assert!(rendered.contains("<cdn_confidence>high</cdn_confidence>"));
    }
}
