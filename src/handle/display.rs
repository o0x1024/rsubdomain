use crate::handle::{AggregatedDiscoveredDomain, SummaryStats, VerificationResult};

pub(crate) fn print_discovered(discovered: &crate::handle::DiscoveredDomain) {
    let display_ip = if discovered.record_type == "TXT" && discovered.ip.len() > 15 {
        format!("{}...", &discovered.ip[..12])
    } else {
        discovered.ip.clone()
    };

    println!(
        "{:<30} {:<8} {:<50} {:<10} {}",
        discovered.domain,
        discovered.query_type,
        display_ip,
        discovered.record_type,
        chrono::DateTime::from_timestamp(discovered.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%H:%M:%S")
    );
}

pub(crate) fn print_dns_header() {
    println!(
        "\n{:<30} {:<8} {:<45} {:<7} {:<20}",
        "域名", "查询", "IP地址", "记录类型", "时间戳"
    );
    println!("{}", "-".repeat(120));
}

pub fn print_aggregated_domains(results: &[AggregatedDiscoveredDomain]) {
    if results.is_empty() {
        return;
    }

    println!(
        "\n{:<30} {:<18} {:<64} {:<8} {:<20}",
        "域名", "记录分布", "解析值", "原始数", "最后时间"
    );
    println!("{}", "-".repeat(148));

    for result in results {
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
            "{:<30} {:<18} {:<64} {:<8} {}",
            result.domain,
            truncate_display(&record_summary, 18),
            truncate_display(&value_summary, 64),
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
    println!("已验证域名: {}", summary.verified_domains);
    println!("存活域名: {}", summary.alive_domains);

    println!("\n记录类型分布:");
    for (record_type, count) in &summary.record_types {
        println!("  {}: {}", record_type, count);
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
