use clap::Parser;
use log::info;
use log::LevelFilter;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsubdomain::{
    device, export_scan_data, flush_raw_record_output, logger, print_aggregated_domains, print_summary_stats,
    print_verification_result, resolve_resolver_input, resolve_target_domain_input,
    BruteForceProgress, BruteForceProgressPhase, ProgressCallback,
    CdnAnalysisOptions, Opts, OutputFormat, SpeedTester, SubdomainBruteConfig,
    SubdomainBruteEngine, SubdomainScanData,
};

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    let log_level = if opts.slient {
        LevelFilter::Off
    } else {
        LevelFilter::Info
    };
    let _ = logger::init_logger(log_level);

    if opts.list_network {
        device::print_network_devices();
        return;
    }

    if opts.network_test {
        if let Err(error) = run_network_speed_test(&opts.target_ip).await {
            eprintln!("网速测试失败: {}", error);
        }
        return;
    }

    if let Err(error) = run_subdomain_brute(opts).await {
        eprintln!("域名暴破失败: {}", error);
    }
}

async fn run_network_speed_test(target_ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tester = SpeedTester::new_with_target(target_ip).await?;
    let result = tester.run_speed_test(10).await;
    tester.display_result(&result);
    Ok(())
}

async fn run_subdomain_brute(opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    let domain_input = resolve_target_domain_input(&opts)?;
    let resolver_input = resolve_resolver_input(&opts)?;
    let progress_callback = build_progress_callback(!opts.slient);

    if !opts.slient {
        info!(
            "目标域名: {} 个（原始输入 {}，排除 {}）",
            domain_input.domains.len(),
            domain_input.input_count,
            domain_input.excluded_count
        );
        info!(
            "DNS解析器: {} 个{}",
            resolver_input.resolvers.len(),
            if resolver_input.input_count == 0 {
                "，使用内置默认解析器".to_string()
            } else {
                String::new()
            }
        );
        info!(
            "运行控制: retry={}, dns-timeout={}s, wait={}s, verify-timeout={}s, verify-concurrency={}, bandwidth={}, transport={:?}, cdn-detect={}, cdn-collapse={}",
            opts.retry,
            opts.dns_timeout,
            opts.wait_seconds,
            opts.verify_timeout,
            opts.verify_concurrency,
            opts.bandwidth,
            opts.transport,
            resolve_cdn_detect(&opts),
            resolve_cdn_collapse(&opts)
        );
    }

    let engine = SubdomainBruteEngine::new(SubdomainBruteConfig {
        domains: domain_input.domains,
        resolvers: resolver_input.resolvers,
        dictionary_file: opts.file.clone(),
        dictionary: None,
        skip_wildcard: opts.skip_wildcard,
        bandwidth_limit: Some(opts.bandwidth.clone()),
        verify_mode: opts.verify,
        max_retries: opts.retry,
        dns_timeout_seconds: opts.dns_timeout,
        max_wait_seconds: opts.wait_seconds,
        verify_timeout_seconds: opts.verify_timeout,
        verify_concurrency: opts.verify_concurrency,
        resolve_records: opts.resolve_records,
        cdn_detect: resolve_cdn_detect(&opts),
        cdn_collapse: resolve_cdn_collapse(&opts),
        query_types: opts.query_types.clone(),
        silent: opts.slient,
        raw_records: opts.raw_records,
        device: opts.device.clone(),
        transport: opts.transport,
        progress_callback,
    })
    .await?;

    let results = engine.run_brute_force().await?;
    flush_raw_record_output();
    let scan_data = SubdomainScanData::from_results_with_options(
        &results,
        CdnAnalysisOptions {
            detect: resolve_cdn_detect(&opts),
            collapse: resolve_cdn_collapse(&opts),
        },
    );

    if !opts.slient && !opts.raw_records {
        print_aggregated_domains(&scan_data.aggregated_domains);
    }

    if opts.verify {
        for result in &scan_data.verification_results {
            print_verification_result(result);
        }
    }

    if opts.summary {
        print_summary_stats(&scan_data.summary);
    }

    if let Some(output_path) = opts.output {
        let format = opts.format.parse::<OutputFormat>().unwrap_or_else(|error| {
            eprintln!("输出格式解析错误: {}, 使用默认JSON格式", error);
            OutputFormat::Json
        });

        export_scan_data(&scan_data, &output_path, &format)?;
    }

    Ok(())
}

fn build_progress_callback(enabled: bool) -> Option<ProgressCallback> {
    if !enabled {
        return None;
    }

    #[derive(Debug)]
    struct ProgressLogState {
        last_phase: Option<BruteForceProgressPhase>,
        last_logged_at: Instant,
        last_sent_queries: usize,
    }

    let state = Arc::new(Mutex::new(ProgressLogState {
        last_phase: None,
        last_logged_at: Instant::now() - Duration::from_secs(5),
        last_sent_queries: 0,
    }));

    Some(Arc::new(move |progress: BruteForceProgress| {
        let mut state = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        let now = Instant::now();
        let phase_changed = state.last_phase != Some(progress.phase);
        let sending_finished = progress.sent_queries == progress.total_queries;
        let should_log = match progress.phase {
            BruteForceProgressPhase::SendingQueries => {
                phase_changed
                    || progress.sent_queries == 1
                    || sending_finished
                    || (now.duration_since(state.last_logged_at) >= Duration::from_secs(1)
                        && progress.sent_queries > state.last_sent_queries)
            }
            BruteForceProgressPhase::WaitingForResponses => {
                phase_changed || now.duration_since(state.last_logged_at) >= Duration::from_secs(1)
            }
            BruteForceProgressPhase::Completed => true,
        };

        if !should_log {
            return;
        }

        state.last_phase = Some(progress.phase);
        state.last_logged_at = now;
        state.last_sent_queries = progress.sent_queries;

        match progress.phase {
            BruteForceProgressPhase::SendingQueries => {
                let percentage = if progress.total_queries == 0 {
                    100.0
                } else {
                    (progress.sent_queries as f64 / progress.total_queries as f64) * 100.0
                };
                info!(
                    "发送进度: {}/{} ({:.1}%), 已发现 {}",
                    progress.sent_queries,
                    progress.total_queries,
                    percentage,
                    progress.discovered_domains
                );
            }
            BruteForceProgressPhase::WaitingForResponses => {
                info!(
                    "等待响应: 已发送 {}, 已发现 {}",
                    progress.sent_queries, progress.discovered_domains
                );
            }
            BruteForceProgressPhase::Completed => {
                info!(
                    "扫描完成: 已发送 {}, 已发现 {}",
                    progress.sent_queries, progress.discovered_domains
                );
            }
        }
    }))
}

fn resolve_cdn_detect(opts: &Opts) -> bool {
    if opts.no_cdn_detect {
        return false;
    }

    if opts.cdn_detect {
        return true;
    }

    true
}

fn resolve_cdn_collapse(opts: &Opts) -> bool {
    if opts.no_cdn_collapse {
        return false;
    }

    if opts.cdn_collapse {
        return true;
    }

    true
}
