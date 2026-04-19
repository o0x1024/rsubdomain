use clap::Parser;
use log::info;
use log::LevelFilter;

use rsubdomain::{
    device, export_scan_data, logger, print_aggregated_domains, print_summary_stats,
    print_verification_result, resolve_resolver_input, resolve_target_domain_input, Opts,
    OutputFormat, SpeedTester, SubdomainBruteConfig, SubdomainBruteEngine, SubdomainScanData,
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
            "运行控制: retry={}, wait={}s, verify-timeout={}s, verify-concurrency={}",
            opts.retry, opts.wait_seconds, opts.verify_timeout, opts.verify_concurrency
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
        max_wait_seconds: opts.wait_seconds,
        verify_timeout_seconds: opts.verify_timeout,
        verify_concurrency: opts.verify_concurrency,
        resolve_records: opts.resolve_records,
        query_types: opts.query_types.clone(),
        silent: opts.slient,
        raw_records: opts.raw_records,
        device: opts.device.clone(),
        progress_callback: None,
    })
    .await?;

    let results = engine.run_brute_force().await?;
    let scan_data = SubdomainScanData::from_results(&results);

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
