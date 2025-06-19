use clap::Parser;

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
            _ => Err(format!("不支持的输出格式: {}。支持的格式: json, xml, csv, txt", s)),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "rsubdomain")]
#[command(author = "gelenlen")]
#[command(version = "1.0")]
#[command(about = "A tool for brute-forcing subdomains", long_about = None,arg_required_else_help = true)]
pub struct Opts {
    /// need scan domain
    #[arg(short, long)]
    pub domain: Vec<String>,

    /// list network
    #[arg(short, long)]
    pub list_network: bool,

    /// resolvers path,use default dns on default
    #[arg(short, long)]
    pub resolvers: Vec<String>,

    /// slient
    #[arg(short, long, default_value = "false")]
    pub slient: bool,

    /// dic path
    #[arg(short, long )]
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

    /// resolve DNS records (A, CNAME, NS, etc.)
    #[arg(long)]
    pub resolve_records: bool,

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
