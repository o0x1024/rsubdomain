use crate::handle::{AggregatedDiscoveredDomain, SummaryStats, VerificationResult};
use std::sync::{Mutex, OnceLock};

const RAW_RECORD_FLUSH_BATCH: usize = 32;

static RAW_RECORD_BUFFER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

pub(crate) fn print_discovered(discovered: &crate::handle::DiscoveredDomain) {
    let display_value = if discovered.record_type == "TXT" && discovered.value.len() > 15 {
        format!("{}...", &discovered.value[..12])
    } else {
        discovered.value.clone()
    };

    let line = format!(
        "{:<30} {:<8} {:<50} {:<10} {}",
        discovered.domain,
        discovered.query_type,
        display_value,
        discovered.record_type,
        chrono::DateTime::from_timestamp(discovered.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%H:%M:%S")
    );

    let buffer = RAW_RECORD_BUFFER.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut lines) = buffer.lock() {
        lines.push(line);
        if lines.len() < RAW_RECORD_FLUSH_BATCH {
            return;
        }
    } else {
        println!("{}", line);
        return;
    }

    flush_raw_record_output();
}

pub(crate) fn print_dns_header() {
    flush_raw_record_output();
    println!(
        "\n{:<30} {:<8} {:<45} {:<7} {:<20}",
        "域名", "查询", "记录值", "记录类型", "时间戳"
    );
    println!("{}", "-".repeat(120));
}

pub fn flush_raw_record_output() {
    let Some(buffer) = RAW_RECORD_BUFFER.get() else {
        return;
    };
    let drained = match buffer.lock() {
        Ok(mut lines) => lines.drain(..).collect::<Vec<_>>(),
        Err(_) => return,
    };

    for line in drained {
        println!("{}", line);
    }
}

pub fn print_aggregated_domains(results: &[AggregatedDiscoveredDomain]) {
    if results.is_empty() {
        return;
    }

    println!(
        "\n{:<30} {:<22} {:<18} {:<52} {:<8} {:<20}",
        "域名", "标签", "记录分布", "解析值", "原始数", "最后时间"
    );
    println!("{}", "-".repeat(160));

    for result in results {
        let tag_summary = format_cdn_tag(result);
        let record_summary = result
            .records
            .iter()
            .map(|record| format!("{}({})", record.record_type, record.values.len()))
            .collect::<Vec<_>>()
            .join(", ");
        let value_summary = result
            .records
            .iter()
            .map(|record| {
                format!(
                    "{}: {}",
                    record.record_type,
                    join_limited(&record.values, 3)
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");

        println!(
            "{:<30} {:<22} {:<18} {:<52} {:<8} {}",
            result.domain,
            truncate_display(&tag_summary, 22),
            truncate_display(&record_summary, 18),
            truncate_display(&value_summary, 52),
            result.raw_record_count,
            chrono::DateTime::from_timestamp(result.last_seen as i64, 0)
                .unwrap_or_default()
                .format("%H:%M:%S")
        );
    }
}

/// 实时打印验证结果
pub fn print_verification_result(result: &VerificationResult) {
    static HEADER_PRINTED: std::sync::Once = std::sync::Once::new();

    HEADER_PRINTED.call_once(|| {
        println!(
            "\n{:<30} {:<15} {:<6} {:<6} {:<20} {:<10}",
            "域名", "IP地址", "HTTP", "HTTPS", "标题", "存活"
        );
        println!("{}", "-".repeat(90));
    });

    println!("{}", result);
}

/// 打印汇总信息
pub fn print_summary_stats(summary: &SummaryStats) {
    println!("\n{}", "=".repeat(60));
    println!("                    汇总统计");
    println!("{}", "=".repeat(60));

    println!("发现记录总数: {}", summary.total_domains);
    println!("唯一域名数量: {}", summary.unique_domains);
    println!("唯一IP数量: {}", summary.unique_ips.len());
    println!("CDN域名数量: {}", summary.cdn_domains);
    println!("疑似CDN域名数量: {}", summary.suspected_cdn_domains);
    println!("已验证域名: {}", summary.verified_domains);
    println!("存活域名: {}", summary.alive_domains);

    println!("\n记录类型分布:");
    for (record_type, count) in &summary.record_types {
        println!("  {}: {}", record_type, count);
    }

    if !summary.cdn_providers.is_empty() {
        println!("\nCDN提供商分布:");
        let mut providers = summary.cdn_providers.iter().collect::<Vec<_>>();
        providers.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
        for (provider, count) in providers {
            println!("  {}: {}", provider, count);
        }
    }

    if !summary.cdn_confidence.is_empty() {
        println!("\nCDN置信度分布:");
        let mut confidence = summary.cdn_confidence.iter().collect::<Vec<_>>();
        confidence.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
        for (level, count) in confidence {
            println!("  {}: {}", level, count);
        }
    }

    println!("\nIP段分布 (前10个):");
    let mut sorted_ranges: Vec<_> = summary.ip_ranges.iter().collect();
    sorted_ranges.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    for (range, ips) in sorted_ranges.iter().take(10) {
        println!("  {}: {} 个IP", range, ips.len());
    }

    if !summary.unique_ips.is_empty() {
        println!("\n发现的IP地址 (前20个):");
        let mut sorted_ips: Vec<_> = summary.unique_ips.iter().collect();
        sorted_ips.sort();
        for ip in sorted_ips.iter().take(20) {
            println!("  {}", ip);
        }
        if summary.unique_ips.len() > 20 {
            println!("  ... 还有 {} 个IP", summary.unique_ips.len() - 20);
        }
    }

    println!("{}", "=".repeat(60));
}

fn join_limited(values: &[String], max_items: usize) -> String {
    let mut preview = values.iter().take(max_items).cloned().collect::<Vec<_>>();
    if values.len() > max_items {
        preview.push(format!("+{} more", values.len() - max_items));
    }
    preview.join(", ")
}

fn truncate_display(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }

    let truncated = value.chars().take(max_chars).collect::<String>();
    format!("{}...", truncated)
}

fn format_cdn_tag(result: &AggregatedDiscoveredDomain) -> String {
    if result.has_cdn {
        return match (
            result.cdn_provider.as_deref(),
            result.cdn_confidence.as_ref(),
        ) {
            (Some(provider), Some(confidence)) => format!("CDN({}): {}", confidence, provider),
            (Some(provider), None) => format!("CDN: {}", provider),
            (None, Some(confidence)) => format!("CDN({})", confidence),
            (None, None) => "CDN".to_string(),
        };
    }

    if result.possible_cdn {
        return "Possible CDN".to_string();
    }

    "-".to_string()
}
