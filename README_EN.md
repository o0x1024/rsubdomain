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
|  | `--wait-seconds` | Max wait time after sending packets | `300` |
|  | `--verify-timeout` | HTTP/HTTPS verification timeout in seconds | `10` |
|  | `--verify-concurrency` | HTTP/HTTPS verification concurrency | `50` |
|  | `--resolve-records` | Resolve DNS records | `false` |
|  | `--qtype` | Query types to send (`a/aaaa/cname/mx/ns/txt`) | `a` |
| `-e` | `--device` | Specify a network device manually | Auto-detect |
| `-o` | `--output` | Output file path | - |
|  | `--format` | Output format (`json/xml/csv/txt`) | `json` |
|  | `--summary` | Show summary statistics | `false` |
|  | `--raw-records` | Print raw DNS records instead of the aggregated host view | `false` |

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
rsubdomain = "1.2.13"
tokio = { version = "1.0", features = ["full"] }
```

If you only want the core library without CLI / verification / DNS record resolution / export / speed-test features:

```toml
[dependencies]
rsubdomain = { version = "1.2.13", default-features = false }
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
