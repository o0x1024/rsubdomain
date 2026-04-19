use log::info;
use std::fs::File;
use std::io::Write;

use crate::api::{SubdomainResult, SubdomainScanData};
use crate::handle::{
    AggregatedDiscoveredDomain, DiscoveredDomain, SummaryStats, VerificationResult,
};
use crate::input::OutputFormat;
use crate::output::formats::{render_csv, render_txt, render_xml};
use crate::output::model::ExportData;

/// 导出结果到文件
pub fn export_results(
    raw_results: Vec<SubdomainResult>,
    discovered: Vec<DiscoveredDomain>,
    aggregated: Vec<AggregatedDiscoveredDomain>,
    verified: Vec<VerificationResult>,
    summary: SummaryStats,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let export_data = ExportData {
        raw_results: raw_results.into_iter().map(Into::into).collect(),
        discovered_domains: discovered.into_iter().map(Into::into).collect(),
        aggregated_domains: aggregated.into_iter().map(Into::into).collect(),
        verification_results: verified.into_iter().map(Into::into).collect(),
        summary: summary.into(),
        export_time: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
    };

    write_export_data(&export_data, output_path, format)?;
    info!("结果已导出到: {}", output_path);
    Ok(())
}

pub fn export_scan_data(
    scan_data: &SubdomainScanData,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    export_results(
        scan_data.raw_results.clone(),
        scan_data.discovered_domains.clone(),
        scan_data.aggregated_domains.clone(),
        scan_data.verification_results.clone(),
        scan_data.summary.clone(),
        output_path,
        format,
    )
}

pub fn export_subdomain_results(
    results: &[SubdomainResult],
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan_data = SubdomainScanData::from_results(results);
    export_scan_data(&scan_data, output_path, format)
}

fn write_export_data(
    data: &ExportData,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(output_path)?;
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(data)?,
        OutputFormat::Xml => render_xml(data),
        OutputFormat::Csv => render_csv(data),
        OutputFormat::Txt => render_txt(data),
    };
    file.write_all(rendered.as_bytes())?;
    Ok(())
}
