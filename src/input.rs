use crate::QueryType;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, Read};

/// 输出格式枚举
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Xml,
    Csv,
    Txt,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "xml" => Ok(OutputFormat::Xml),
            "csv" => Ok(OutputFormat::Csv),
            "txt" => Ok(OutputFormat::Txt),
            _ => Err(format!(
                "不支持的输出格式: {}。支持的格式: json, xml, csv, txt",
                s
            )),
        }
    }
}

#[cfg(feature = "cli")]
use clap::value_parser;
#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
#[derive(Debug, Clone)]
pub struct TargetDomainInput {
    pub domains: Vec<String>,
    pub input_count: usize,
    pub excluded_count: usize,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone)]
pub struct ResolverInput {
    pub resolvers: Vec<String>,
    pub input_count: usize,
}

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(name = "rsubdomain")]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Opts {
    /// need scan domain
    #[arg(short, long)]
    pub domain: Vec<String>,

    /// load domains from file, one per line
    #[arg(long)]
    pub domain_file: Option<String>,

    /// read domains from stdin, one per line
    #[arg(long)]
    pub stdin: bool,

    /// exclude domains from scanning
    #[arg(long, value_delimiter = ',')]
    pub exclude_domain: Vec<String>,

    /// load excluded domains from file, one per line
    #[arg(long)]
    pub exclude_domain_file: Option<String>,

    /// list network
    #[arg(short, long)]
    pub list_network: bool,

    /// resolvers path,use default dns on default
    #[arg(short, long)]
    pub resolvers: Vec<String>,

    /// load resolvers from file, one per line
    #[arg(long)]
    pub resolver_file: Option<String>,

    /// slient
    #[arg(short, long, visible_alias = "silent", default_value = "false")]
    pub slient: bool,

    /// dic path
    #[arg(short, long)]
    pub file: Option<String>,

    /// skip wildcard domains
    #[arg(short = 'w', long, default_value = "true")]
    pub skip_wildcard: bool,

    /// network speed test
    #[arg(short = 'n', long)]
    pub network_test: bool,

    /// target IP for network speed test (default: 8.8.8.8)
    #[arg(long, default_value = "8.8.8.8")]
    pub target_ip: String,

    /// bandwidth limit (e.g., 3M, 5K, 10G)
    #[arg(short, long, default_value = "3M")]
    pub bandwidth: String,

    /// verify mode - check HTTP/HTTPS after domain discovery
    #[arg(short, long)]
    pub verify: bool,

    /// max retry count for timed out DNS queries
    #[arg(long, default_value_t = 5, value_parser = value_parser!(u8).range(1..))]
    pub retry: u8,

    /// max wait time in seconds after sending queries
    #[arg(long = "wait-seconds", default_value_t = 300, value_parser = value_parser!(u64).range(1..))]
    pub wait_seconds: u64,

    /// HTTP/HTTPS verification timeout in seconds
    #[arg(long = "verify-timeout", default_value_t = 10, value_parser = value_parser!(u64).range(1..))]
    pub verify_timeout: u64,

    /// HTTP/HTTPS verification concurrency
    #[arg(long = "verify-concurrency", default_value_t = 50)]
    pub verify_concurrency: usize,

    /// resolve DNS records (A, CNAME, NS, etc.)
    #[arg(long)]
    pub resolve_records: bool,

    /// query types to send (comma separated, e.g. a,aaaa,cname)
    #[arg(long = "qtype", value_delimiter = ',', default_values_t = [QueryType::A])]
    pub query_types: Vec<QueryType>,

    /// manually specify network device
    #[arg(short = 'e', long)]
    pub device: Option<String>,

    /// output file path
    #[arg(short, long)]
    pub output: Option<String>,

    /// output format (json, xml, csv, txt)
    #[arg(long, default_value = "json")]
    pub format: String,

    /// show summary statistics
    #[arg(long)]
    pub summary: bool,

    /// print raw DNS records instead of aggregated host view
    #[arg(long)]
    pub raw_records: bool,
}

/// 解析带宽字符串为字节/秒
pub fn parse_bandwidth(bandwidth: &str) -> Result<u64, String> {
    let bandwidth = bandwidth.to_uppercase();
    let (num_str, unit) = if bandwidth.ends_with("K") {
        (bandwidth.trim_end_matches("K"), "K")
    } else if bandwidth.ends_with("M") {
        (bandwidth.trim_end_matches("M"), "M")
    } else if bandwidth.ends_with("G") {
        (bandwidth.trim_end_matches("G"), "G")
    } else {
        return Err("Invalid bandwidth format. Use K, M, or G suffix.".to_string());
    };

    let num: f64 = num_str.parse().map_err(|_| "Invalid number in bandwidth")?;

    let bytes_per_sec = match unit {
        "K" => (num * 1024.0) as u64,
        "M" => (num * 1024.0 * 1024.0) as u64,
        "G" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => return Err("Invalid unit".to_string()),
    };

    Ok(bytes_per_sec)
}

#[cfg(feature = "cli")]
pub fn resolve_target_domains(opts: &Opts) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(resolve_target_domain_input(opts)?.domains)
}

#[cfg(feature = "cli")]
pub fn resolve_target_domain_input(
    opts: &Opts,
) -> Result<TargetDomainInput, Box<dyn std::error::Error>> {
    let mut domains = Vec::new();
    domains.extend(normalize_domain_entries(opts.domain.clone()));

    if let Some(domain_file) = opts.domain_file.as_deref() {
        domains.extend(load_domains_from_file(domain_file)?);
    }

    if opts.stdin {
        domains.extend(load_domains_from_stdin()?);
    }

    let domains = dedupe_domains(domains);
    let input_count = domains.len();
    let excluded_domains = resolve_excluded_domains(opts)?;

    let filtered_domains = domains
        .into_iter()
        .filter(|domain| !excluded_domains.contains(domain))
        .collect::<Vec<_>>();

    if filtered_domains.is_empty() {
        return Err("未提供有效的目标域名。请使用 -d、--domain-file 或 --stdin".into());
    }

    Ok(TargetDomainInput {
        domains: filtered_domains,
        input_count,
        excluded_count: excluded_domains.len(),
    })
}

#[cfg(feature = "cli")]
pub fn resolve_resolver_input(opts: &Opts) -> Result<ResolverInput, Box<dyn std::error::Error>> {
    let mut resolvers = normalize_resolver_entries(opts.resolvers.clone());

    if let Some(resolver_file) = opts.resolver_file.as_deref() {
        resolvers.extend(load_resolvers_from_file(resolver_file)?);
    }

    let resolvers = dedupe_domains(resolvers);
    let input_count = resolvers.len();

    Ok(ResolverInput {
        resolvers,
        input_count,
    })
}

#[cfg(feature = "cli")]
fn resolve_excluded_domains(opts: &Opts) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut excluded_domains = normalize_domain_entries(opts.exclude_domain.clone());

    if let Some(exclude_domain_file) = opts.exclude_domain_file.as_deref() {
        excluded_domains.extend(load_domains_from_file(exclude_domain_file)?);
    }

    Ok(dedupe_domains(excluded_domains).into_iter().collect())
}

fn load_domains_from_file(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader.lines().collect::<Result<Vec<_>, _>>()?;
    Ok(normalize_domain_entries(lines))
}

fn load_resolvers_from_file(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader.lines().collect::<Result<Vec<_>, _>>()?;
    Ok(normalize_resolver_entries(lines))
}

fn load_domains_from_stdin() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(normalize_domain_entries(
        buffer
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>(),
    ))
}

fn normalize_domain_entries<I>(entries: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    entries
        .into_iter()
        .filter_map(|entry| normalize_domain(entry.as_str()))
        .collect()
}

fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty() || domain.starts_with('#') || domain.chars().any(char::is_whitespace) {
        return None;
    }

    Some(domain)
}

fn normalize_resolver_entries<I>(entries: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    entries
        .into_iter()
        .filter_map(|entry| normalize_resolver(entry.as_str()))
        .collect()
}

fn normalize_resolver(resolver: &str) -> Option<String> {
    let resolver = resolver.trim().to_ascii_lowercase();

    if resolver.is_empty() || resolver.starts_with('#') || resolver.chars().any(char::is_whitespace)
    {
        return None;
    }

    Some(resolver)
}

fn dedupe_domains(domains: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for domain in domains {
        if seen.insert(domain.clone()) {
            deduped.push(domain);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::{
        dedupe_domains, normalize_domain, normalize_domain_entries, normalize_resolver,
        normalize_resolver_entries,
    };

    #[test]
    fn normalize_domain_strips_noise_and_lowercases() {
        assert_eq!(
            normalize_domain("  WWW.Example.com. "),
            Some("www.example.com".to_string())
        );
        assert_eq!(normalize_domain("# comment"), None);
        assert_eq!(normalize_domain("api example.com"), None);
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn normalize_domain_entries_skips_invalid_values() {
        let normalized = normalize_domain_entries(vec![
            "Example.com".to_string(),
            " ".to_string(),
            "# ignored".to_string(),
            "api.example.com.".to_string(),
        ]);

        assert_eq!(normalized, vec!["example.com", "api.example.com"]);
    }

    #[test]
    fn dedupe_domains_keeps_first_occurrence_order() {
        let deduped = dedupe_domains(vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
            "a.example.com".to_string(),
        ]);

        assert_eq!(deduped, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn dedupe_domains_handles_empty_input() {
        let deduped = dedupe_domains(Vec::new());

        assert!(deduped.is_empty());
    }

    #[test]
    fn normalize_resolver_strips_noise_and_lowercases() {
        assert_eq!(
            normalize_resolver("  8.8.8.8  "),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(
            normalize_resolver("  2001:DB8::1  "),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(normalize_resolver("# comment"), None);
        assert_eq!(normalize_resolver("8.8.8.8 1.1.1.1"), None);
    }

    #[test]
    fn normalize_resolver_entries_skips_invalid_values() {
        let normalized = normalize_resolver_entries(vec![
            "8.8.8.8".to_string(),
            " ".to_string(),
            "# ignored".to_string(),
            "1.1.1.1".to_string(),
        ]);

        assert_eq!(normalized, vec!["8.8.8.8", "1.1.1.1"]);
    }
}
