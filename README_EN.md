# rsubdomain

[中文](README.md) | [English](README_EN.md)

`rsubdomain` is a high-performance subdomain brute-force tool written in Rust. Its design is inspired by [ksubdomain](https://github.com/knownsec/ksubdomain).

## Why rsubdomain

- High performance: builds DNS packets directly and combines link-layer packet injection with a UDP-compatible fallback path.
- Rich functionality: subdomain discovery, HTTP/HTTPS verification, and DNS record resolution.
- Multiple export formats: JSON, XML, CSV, and TXT.
- Smart network handling: auto-detects the best network device and also supports manual device selection.
- Built-in speed test: includes a DNS packet send speed benchmark.
- Wildcard support: can detect and filter wildcard DNS responses, or skip that step when needed.
- Live statistics: supports real-time output and summary statistics.

## Requirements

The project does not directly depend on `libpcap` development packages on Linux/macOS. It mainly relies on the Rust toolchain and the operating system's native packet I/O capabilities.

### Linux/macOS

- Install a working Rust toolchain.
- Make sure the current environment can access the required link-layer packet send/receive interfaces.

### macOS notes

- The high-performance path accesses macOS BPF devices.
- If BPF permissions are not configured, you will usually need `sudo`.
- If Wireshark's `ChmodBPF`/`chmodbpf` component is installed and your user has BPF access, you can run it as a normal user without `root`.

### Windows

You need:

1. A Rust toolchain with the MSVC target.
2. [WinPcap](https://www.winpcap.org/) or [Npcap](https://nmap.org/npcap/) installed. Npcap is recommended, with WinPcap compatibility enabled.
3. `Packet.lib` from [WinPcap Developers](https://www.winpcap.org/devel.htm) placed in the local `lib/` directory.

## Build

```bash
git clone https://github.com/o0x1024/rsubdomain
cd rsubdomain
cargo build --release
```

## Usage

### Basic examples

```bash
# Basic scan
./rsubdomain -d example.com

# Specify resolvers directly
./rsubdomain -d example.com -r 8.8.8.8 -r 1.1.1.1

# Use a custom dictionary file
./rsubdomain -d example.com -f wordlist.txt

# Read domains from file
./rsubdomain --domain-file domains.txt

# Read domains from stdin
cat domains.txt | ./rsubdomain --stdin

# Exclude domains
./rsubdomain --domain-file domains.txt --exclude-domain dev.example.com,test.example.com

# Load exclusions from file
./rsubdomain --domain-file domains.txt --exclude-domain-file excludes.txt

# Load resolvers from file
./rsubdomain -d example.com --resolver-file resolvers.txt

# Runtime controls
./rsubdomain -d example.com --retry 3 --wait-seconds 120 --verify-timeout 5 --verify-concurrency 20 -v

# Multiple query types
./rsubdomain -d example.com --qtype a,aaaa,cname

# Skip wildcard detection/filtering
./rsubdomain -d example.com --skip-wildcard

# Silent mode
./rsubdomain -d example.com --silent

# Scan multiple domains
./rsubdomain -d example.com -d test.com
```

### Network features

```bash
# List network interfaces
./rsubdomain -l

# Speed test (default target: 8.8.8.8)
./rsubdomain -n

# Speed test with a custom target
./rsubdomain -n --target-ip 1.1.1.1

# Specify a device manually
./rsubdomain -d example.com -e eth0

# Limit bandwidth
./rsubdomain -d example.com -b 5M
```

### Verification and DNS record resolution

```bash
# HTTP/HTTPS verification
./rsubdomain -d example.com -v

# Resolve DNS records
./rsubdomain -d example.com --resolve-records

# Print raw per-record output
./rsubdomain -d example.com --qtype a,txt --raw-records

# Combine verification and record resolution
./rsubdomain -d example.com -v --resolve-records

# Disable CDN detection in the aggregated asset view
./rsubdomain -d example.com --no-cdn-detect

# Keep all CDN-backed A/AAAA records in the aggregated asset view
./rsubdomain -d example.com --resolve-records --no-cdn-collapse

# Print summary with CDN statistics
./rsubdomain -d example.com --resolve-records --summary
```

### Output and statistics

```bash
# Show summary
./rsubdomain -d example.com --summary

# Export as JSON
./rsubdomain -d example.com -o results.json --format json

# Export as CSV
./rsubdomain -d example.com -o results.csv --format csv

# Export as XML
./rsubdomain -d example.com -o results.xml --format xml

# Export as TXT
./rsubdomain -d example.com -o results.txt --format txt
```

## CLI arguments

| Short | Long | Description | Default |
|------|------|-------------|---------|
| `-d` | `--domain` | Target domain(s) to scan | Use with `--domain-file` / `--stdin` as needed |
|  | `--domain-file` | Load target domains from file, one per line | - |
|  | `--stdin` | Read target domains from stdin, one per line | `false` |
|  | `--exclude-domain` | Exclude domains, comma-separated | - |
|  | `--exclude-domain-file` | Load excluded domains from file, one per line | - |
| `-l` | `--list-network` | List network interfaces | - |
| `-r` | `--resolvers` | Specify resolver IPs directly, repeatable | Built-in public resolver list |
|  | `--resolver-file` | Load resolvers from file, one per line | - |
| `-s` | `--silent` | Silent mode, only print discovered domains (`--slient` is kept as a legacy alias) | `false` |
| `-f` | `--file` | Custom dictionary file path | Embedded default dictionary |
| `-w` | `--skip-wildcard` | Skip wildcard detection and filtering | `false` |
| `-n` | `--network-test` | Run the network speed test | - |
|  | `--target-ip` | Target IP for the speed test | `8.8.8.8` |
| `-b` | `--bandwidth` | Bandwidth limit (`K` / `M` / `G`) | `3M` |
| `-v` | `--verify` | Enable HTTP/HTTPS verification | `false` |
|  | `--retry` | Max retries after DNS timeout | `5` |
|  | `--wait-seconds` | Max wait time after sending packets | `10` |
|  | `--verify-timeout` | HTTP/HTTPS verification timeout in seconds | `10` |
|  | `--verify-concurrency` | HTTP/HTTPS verification concurrency | `50` |
|  | `--resolve-records` | Resolve DNS records | `false` |
|  | `--cdn-detect` | Explicitly enable CDN detection in the aggregated asset view | `true` |
|  | `--no-cdn-detect` | Disable CDN detection in the aggregated asset view | `false` |
|  | `--cdn-collapse` | Explicitly collapse CDN-backed `A/AAAA` values in the aggregated view | `true` |
|  | `--no-cdn-collapse` | Keep all CDN-backed `A/AAAA` values in the aggregated view | `false` |
|  | `--qtype` | Query types to send (`a/aaaa/cname/mx/ns/txt`) | `a` |
| `-e` | `--device` | Specify a network device manually | Auto-detect |
| `-o` | `--output` | Output file path | - |
|  | `--format` | Output format (`json/xml/csv/txt`) | `json` |
|  | `--summary` | Show summary statistics | `false` |
|  | `--raw-records` | Print raw DNS records instead of the aggregated host view | `false` |

## CDN asset view

- The default output is asset-oriented. It shows only the direct records on the queried hostname and does not expand a `CNAME -> A/AAAA` chain.
- The default terminal view is the aggregated domain view. Use `--raw-records` if you want every discovered record.
- When a domain is classified as CDN-backed, the aggregated view marks it as `CDN(confidence): provider`.
- CDN-backed `A/AAAA` values are collapsed to one representative value by default in the aggregated view, while `raw_record_count` preserves the real count.
- Use `--no-cdn-collapse` to keep every CDN-backed `A/AAAA` value, or `--no-cdn-detect` to disable CDN classification entirely.

### Evidence sources

- `CNAME`: strongest signal for typical CDN onboarding domains
- `NS`: strong signal when authoritative DNS is delegated into a CDN platform
- `PTR`: useful for direct `A/AAAA` CDN edges; requires `--resolve-records`
- `IP_RANGE`: useful for CDN-backed IPs without meaningful PTR names
- `MULTI_A/MULTI_AAAA`: weak signal only; multiple IPs may mean CDN, but may also just mean load balancing or multi-region deployment

### Confidence levels

- `high`: suffix-based `CNAME/NS` match, or `PTR + IP_RANGE`
- `medium`: `PTR` only or `IP_RANGE` only
- `low`: weak name-pattern match only

### Possible CDN

- `has_cdn` is reserved for explicit CDN classification with strong or medium evidence.
- `possible_cdn` is reserved for weak signals, currently `MULTI_A` and `MULTI_AAAA`.
- `possible_cdn` does not trigger CDN IP collapsing and does not count toward `cdn_domains`.

### Rule files

- `data/cdn_rules.txt`
  One rule per line: `Provider,suffix:example.cdn.net,contains:.vendor.`
- `data/cdn_ip_ranges.txt`
  One rule per line: `Provider,203.0.113.0/24`
- `suffix:` uses strict domain-boundary matching.
- `contains:` is only for patterns that truly need substring matching.

## Technical notes

- Packet construction: DNS packets are built and parsed directly.
- Network sending: the engine prefers the link-layer path and falls back to a UDP-compatible mode when no usable MAC-based path is available.
- Async orchestration: Tokio is used to coordinate sending, receiving, retries, and result processing.
- Device detection: the best network interface is selected automatically when possible.
- Structured export: scan data can be exported in multiple machine-readable formats.

## Library usage

`rsubdomain` can also be used as a Rust library.

### Add the dependency

```toml
[dependencies]
rsubdomain = "1.2.14"
tokio = { version = "1.0", features = ["full"] }
```

If you only want the core library without CLI / verification / DNS record resolution / export / speed-test features:

```toml
[dependencies]
rsubdomain = { version = "1.2.14", default-features = false }
tokio = { version = "1.0", features = ["full"] }
```

### Quick start

```rust
use rsubdomain::brute_force_subdomains;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domains = vec!["example.com".to_string()];
    let results = brute_force_subdomains(
        domains,
        None,
        None,
        false,
        None,
        false,
        false,
        false,
        None,
    ).await?;

    println!("found {} subdomains", results.len());
    Ok(())
}
```

### Advanced config

```rust
use rsubdomain::{QueryType, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string()],
        verify_mode: true,
        resolve_records: true,
        cdn_detect: true,
        cdn_collapse: true,
        query_types: vec![QueryType::A, QueryType::Cname, QueryType::Txt],
        ..Default::default()
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    let results = engine.run_brute_force().await?;
    println!("found {} subdomains", results.len());
    Ok(())
}
```

### Example files

- `examples/quick_start.rs`
- `examples/library_usage.rs`

Run them with:

```bash
cargo run --example quick_start
cargo run --example library_usage
```

## Notes

1. Permissions: the high-performance path accesses link-layer packet I/O. Linux usually still requires `root` or equivalent capabilities. On macOS, `sudo` is typically required unless BPF permissions have been configured through `ChmodBPF`/`chmodbpf`.
2. Async runtime: the library must run inside Tokio.
3. Network dependency: use it in a stable network environment.
4. System dependency: Windows requires a compatible Npcap/WinPcap environment; Linux/macOS mainly depend on native network interface permissions.
5. Legal use: only use this tool for authorized security testing and research.

## License

MIT License

## Contributing

Issues and pull requests are welcome.

## Disclaimer

This tool is intended for authorized security testing and research only. Users are responsible for complying with applicable laws and regulations.
