# rsubdomain

[中文](README.md) | [English](README_EN.md)

基于 Rust 实现的高性能子域名暴破工具，实现原理参考 [ksubdomain](https://github.com/knownsec/ksubdomain)

## 为什么选择rsubdomain
- 🚀 **高性能**: 直接构造 DNS 报文，结合链路层发包与 UDP 兼容模式，支持高并发
- 🔍 **功能丰富**: 支持子域名发现、HTTP/HTTPS验证、DNS记录解析
- 📊 **多格式输出**: 支持JSON、XML、CSV、TXT四种输出格式
- 🌐 **智能网络**: 自动检测网络设备，支持手动指定网络接口
- 📈 **网速测试**: 内置DNS包发送速度测试功能
- 🎯 **泛解析检测**: 支持泛解析检测与过滤，可按需跳过
- 📋 **实时统计**: 提供详细的汇总统计信息

## 安装要求
本项目不直接依赖 Linux/macOS 上的 `libpcap` 开发包，主要依赖 Rust 工具链和系统原生网络接口能力。

### Linux/macOS
- 安装可用的 Rust 工具链。
- 确保当前环境允许访问链路层发包/收包接口。

macOS 额外说明：

- 高性能发包/收包路径会访问系统的 BPF 设备。
- 未配置 BPF 设备权限时，通常需要使用 `sudo` 运行。
- 如果已安装 Wireshark 的 `ChmodBPF`/`chmodbpf` 组件，并且当前用户具备对应的 BPF 设备访问权限，则可以直接使用普通用户运行，无需 `root`。

### Windows
需要安装以下组件：
1. 使用MSVC工具链的Rust版本
2. 安装 [WinPcap](https://www.winpcap.org/) 或 [npcap](https://nmap.org/npcap/) (推荐npcap，需选择WinPcap兼容模式)
3. 从 [WinPcap Developers](https://www.winpcap.org/devel.htm) 下载`Packet.lib`并放置在项目根目录的`lib`文件夹中

## 编译安装
```bash
git clone https://github.com/o0x1024/rsubdomain
cd rsubdomain
cargo build --release
```

## 使用方法

### 基本用法
```bash
# 基本子域名扫描
./rsubdomain -d example.com

# 直接指定 DNS 解析器
./rsubdomain -d example.com -r 8.8.8.8 -r 1.1.1.1

# 使用自定义字典文件
./rsubdomain -d example.com -f wordlist.txt

# 从文件读取目标域名
./rsubdomain --domain-file domains.txt

# 从标准输入读取目标域名
cat domains.txt | ./rsubdomain --stdin

# 排除不想扫描的域名
./rsubdomain --domain-file domains.txt --exclude-domain dev.example.com,test.example.com

# 从文件批量排除域名
./rsubdomain --domain-file domains.txt --exclude-domain-file excludes.txt

# 从文件读取DNS解析器
./rsubdomain -d example.com --resolver-file resolvers.txt

# 自定义运行期控制
./rsubdomain -d example.com --retry 3 --wait-seconds 120 --verify-timeout 5 --verify-concurrency 20 -v

# 指定多种查询类型
./rsubdomain -d example.com --qtype a,aaaa,cname

# 跳过泛解析检测与过滤
./rsubdomain -d example.com --skip-wildcard

# 静默模式（只输出发现的域名）
./rsubdomain -d example.com --silent

# 扫描多个域名
./rsubdomain -d example.com -d test.com
```

### 网络功能
```bash
# 列出所有网络接口
./rsubdomain -l

# 网速测试（默认目标8.8.8.8）
./rsubdomain -n

# 指定目标IP进行网速测试
./rsubdomain -n --target-ip 1.1.1.1

# 手动指定网络设备
./rsubdomain -d example.com -e eth0

# 带宽限制
./rsubdomain -d example.com -b 5M
```

### 验证和解析功能
```bash
# HTTP/HTTPS验证模式
./rsubdomain -d example.com -v

# DNS记录解析
./rsubdomain -d example.com --resolve-records

# 输出原始逐记录结果
./rsubdomain -d example.com --qtype a,txt --raw-records

# 同时启用验证和解析
./rsubdomain -d example.com -v --resolve-records
```

### 输出和统计
```bash
# 显示汇总统计
./rsubdomain -d example.com --summary

# 导出为JSON格式
./rsubdomain -d example.com -o results.json --format json

# 导出为CSV格式
./rsubdomain -d example.com -o results.csv --format csv

# 导出为XML格式
./rsubdomain -d example.com -o results.xml --format xml

# 导出为TXT格式
./rsubdomain -d example.com -o results.txt --format txt

# 导出包含查询类型的多记录扫描结果
./rsubdomain -d example.com --qtype a,aaaa,mx -o results.json --format json
```

### 高级用法
```bash
# 完整功能组合使用
./rsubdomain -d example.com -f wordlist.txt -v --resolve-records --summary -o results.json --format json -e eth0 -b 3M
```

## 命令行参数详解

| 参数 | 长参数 | 描述 | 默认值 |
|------|--------|------|--------|
| `-d` | `--domain` | 需要扫描的目标域名（可多个） | 与 `--domain-file` / `--stdin` 三选一即可 |
| | `--domain-file` | 从文件读取目标域名，每行一个 | - |
| | `--stdin` | 从标准输入读取目标域名，每行一个 | false |
| | `--exclude-domain` | 排除的目标域名，可逗号分隔 | - |
| | `--exclude-domain-file` | 从文件读取排除域名，每行一个 | - |
| `-l` | `--list-network` | 列出所有网络接口 | - |
| `-r` | `--resolvers` | 直接指定 DNS 解析器 IP，可重复传入 | 内置公共 DNS 列表 |
| | `--resolver-file` | 从文件读取DNS解析器，每行一个 | - |
| `-s` | `--silent` | 静默模式，只输出域名（兼容历史拼写 `--slient`） | false |
| `-f` | `--file` | 自定义字典文件路径 | 内置字典 |
| `-w` | `--skip-wildcard` | 跳过泛解析检测与过滤 | false |
| `-n` | `--network-test` | 执行网速测试 | - |
| | `--target-ip` | 网速测试目标IP | 8.8.8.8 |
| `-b` | `--bandwidth` | 带宽限制 (K/M/G) | 3M |
| `-v` | `--verify` | HTTP/HTTPS验证模式 | - |
| | `--retry` | DNS查询超时后的最大重试次数 | 5 |
| | `--wait-seconds` | 发包完成后的最大等待时间（秒） | 300 |
| | `--verify-timeout` | HTTP/HTTPS验证超时时间（秒） | 10 |
| | `--verify-concurrency` | HTTP/HTTPS验证并发度 | 50 |
| | `--resolve-records` | 解析DNS记录 | - |
| | `--qtype` | 主动发送的查询类型，可逗号分隔 (a/aaaa/cname/mx/ns/txt) | a |
| `-e` | `--device` | 手动指定网络设备 | 自动检测 |
| `-o` | `--output` | 输出文件路径 | - |
| | `--format` | 输出格式 (json/xml/csv/txt) | json |
| | `--summary` | 显示汇总统计 | - |
| | `--raw-records` | 实时输出逐条DNS记录，而不是聚合视图 | false |

## 输出示例

### 标准输出
```
域名                          查询     IP地址                                         记录类型    时间戳
------------------------------------------------------------------------------------------------------------------------
www.example.com               A        93.184.216.34                                   A          14:23:45
mail.example.com              MX       10 mail.example.com                             MX         14:23:46
ftp.example.com               CNAME    ftp.example.org                                 CNAME      14:23:47
```

### 验证结果输出
```
域名                          IP地址          HTTP   HTTPS  标题                存活
------------------------------------------------------------------------------------------
www.example.com               93.184.216.34   200    200    Example Domain      YES
api.example.com               93.184.216.35   404    N/A    N/A                 NO
```

### 汇总统计
```
============================================================
                    汇总统计
============================================================
发现记录总数: 156
唯一域名数量: 98
唯一IP数量: 23
已验证域名: 45
存活域名: 32

记录类型分布:
  A: 134
  CNAME: 18
  MX: 4

IP段分布 (前10个):
  93.184.216.0/24: 12 个IP
  192.168.1.0/24: 8 个IP
  10.0.0.0/24: 5 个IP
```

## 性能特点

- **高并发**: 支持数万并发DNS查询
- **智能重试**: 自动处理DNS查询超时和失败
- **带宽控制**: 可限制发送速度避免网络拥塞
- **内存优化**: 高效的数据结构减少内存占用
- **实时输出**: 边扫描边输出，无需等待完成

## 技术实现

- **报文构造**: 直接构造和解析 DNS 报文
- **网络发送**: 优先使用链路层通道，在无可用 MAC 的接口上回退到 UDP 兼容模式
- **异步编排**: 基于 Tokio 协调任务和结果处理
- **智能解析**: 正确解析各种DNS记录类型
- **网络检测**: 自动识别最佳网络接口
- **数据导出**: 支持多种结构化数据格式

## 注意事项

1. **权限要求**: 高性能模式会直接访问链路层发包/收包接口。Linux 通常仍需要 `root` 或等效能力；macOS 在未配置 BPF 设备权限时通常需要 `sudo`，安装 Wireshark 的 `ChmodBPF`/`chmodbpf` 并赋予当前用户访问权限后可直接以普通用户运行
2. **防火墙**: 确保DNS流量（UDP 53端口）未被阻止
3. **网络环境**: 建议在稳定的网络环境下使用
4. **目标限制**: 请合理使用，避免对目标造成压力
5. **法律合规**: 仅用于授权的安全测试

## 更新日志

### v1.2.13 (最新)
- 🐛 修复API中`send_dns_queries`方法参数不匹配问题
- 🐛 修复带宽限制器创建和使用逻辑
- 🐛 修复超时域名处理中的变量借用问题
- 🐛 修复资源清理时机导致结果丢失的问题
- ⚡ 优化DNS查询发送逻辑，支持文件和列表两种模式
- ⚡ 改进超时和重试处理机制
- 📚 更新API文档和使用示例
- 🔧 增强错误处理和状态管理

### v1.2.3
- 🐛 修复多个API稳定性问题
- ⚡ 优化内存使用和性能

### v1.2.0
- ✨ 新增HTTP/HTTPS验证功能
- ✨ 新增DNS记录解析功能  
- ✨ 新增多格式输出支持(JSON/XML/CSV/TXT)
- ✨ 新增网速测试功能
- ✨ 新增手动指定网络设备
- ✨ 新增汇总统计功能
- 🐛 修复DNS记录解析显示问题
- 🐛 修复CNAME、MX、TXT记录解析异常
- ⚡ 优化异步处理性能
- 📊 增强实时输出和表格显示

### v1.1.0
- ✨ 新增泛解析检测
- ✨ 新增带宽限制功能
- 🐛 修复多域名扫描问题
- ⚡ 优化内存使用

### v1.0.0
- 🎉 初始版本发布
- ✨ 基本子域名暴破功能
- ✨ 自动网络设备检测


## 作为库使用

rsubdomain不仅可以作为命令行工具使用，还可以作为Rust库集成到你的项目中。

### 添加依赖

在你的`Cargo.toml`中添加依赖：

```toml
[dependencies]
# 从 crates.io
rsubdomain = "1.2.13"

# 或从本地路径 / Git 仓库
# rsubdomain = { path = "/path/to/rsubdomain" }
# rsubdomain = { git = "https://github.com/o0x1024/rsubdomain" }

# 异步运行时（必需）
tokio = { version = "1.0", features = ["full"] }
```

如果你只想把它当作库引用，而不需要 CLI / HTTP 验证 / DNS 记录解析 / 导出 / 网速测试能力，可以关闭默认特性：

```toml
[dependencies]
rsubdomain = { version = "1.2.13", default-features = false }
tokio = { version = "1.0", features = ["full"] }
```

### 快速开始

```rust
use rsubdomain::{brute_force_subdomains, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 方法1: 使用便捷函数（最简单）
    let domains = vec!["example.com".to_string()];
    let results = brute_force_subdomains(
        domains,
        None,
        None,
        true,
        None,
        false,
        false,
        false,
        None,
    ).await?;
    
    println!("发现 {} 个子域名", results.len());
    for result in results.iter().take(5) {
        println!("  {} -> {}", result.domain, result.ip);
    }
    
    Ok(())
}
```

### 高级配置

```rust
use rsubdomain::{export_subdomain_results, OutputFormat, QueryType, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建配置
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string()],
        resolvers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        dictionary_file: Some("wordlist.txt".to_string()),
        skip_wildcard: true,
        bandwidth_limit: Some("5M".to_string()),
        verify_mode: true,      // 启用HTTP/HTTPS验证
        max_retries: 5,
        max_wait_seconds: 300,
        verify_timeout_seconds: 10,
        verify_concurrency: 50,
        resolve_records: true,  // 启用DNS记录解析
        query_types: vec![QueryType::A, QueryType::Aaaa, QueryType::Cname],
        silent: false,
        raw_records: false,     // 默认按域名聚合展示
        device: None, // 自动检测网络设备
        dictionary: None,
        progress_callback: None,
    };

    // 创建暴破引擎
    let engine = SubdomainBruteEngine::new(config).await?;
    
    // 执行暴破
    let results = engine.run_brute_force().await?;
    
    // 处理结果
    for result in &results {
        println!("域名: {}", result.domain);
        println!("  IP: {}", result.ip);
        println!("  查询类型: {}", result.query_type);
        println!("  记录类型: {}", result.record_type);
        
        // 验证结果
        if let Some(ref verified) = result.verified {
            println!("  HTTP状态: {:?}", verified.http_status);
            println!("  HTTPS状态: {:?}", verified.https_status);
            println!("  标题: {:?}", verified.title);
        }
        
        // DNS记录
        if let Some(ref dns_records) = result.dns_records {
            println!("  DNS记录数: {}", dns_records.records.len());
        }
        
        println!();
    }
    
    export_subdomain_results(&results, "results.json", &OutputFormat::Json)?;

    Ok(())
}
```

### API 参考

#### 主要结构体

**`SubdomainBruteConfig`** - 暴破配置
- `domains: Vec<String>` - 目标域名列表
  可由 `-d`、`--domain-file`、`--stdin` 组合输入，并在 CLI 层做去重和排除过滤
- `resolvers: Vec<String>` - DNS服务器列表
  可由 `-r` 和 `--resolver-file` 组合输入，CLI 层会做归一化和去重
- `dictionary_file: Option<String>` - 字典文件路径
- `skip_wildcard: bool` - 是否跳过泛解析检测
- `bandwidth_limit: Option<String>` - 带宽限制
- `verify_mode: bool` - 是否启用HTTP/HTTPS验证
- `max_retries: u8` - DNS超时后的最大重试次数
- `max_wait_seconds: u64` - 发包结束后的最大等待时间
- `verify_timeout_seconds: u64` - HTTP/HTTPS验证超时时间
- `verify_concurrency: usize` - HTTP/HTTPS验证并发度
- `resolve_records: bool` - 是否解析DNS记录
- `query_types: Vec<QueryType>` - 主动发送的DNS查询类型
- `silent: bool` - 静默模式
- `raw_records: bool` - 是否输出原始逐记录结果
- `device: Option<String>` - 网络设备名称

**`SubdomainResult`** - 暴破结果
- `domain: String` - 发现的域名
- `ip: String` - 对应的IP地址
- `query_type: QueryType` - 主动查询类型
- `record_type: String` - DNS记录类型
- `verified: Option<VerifyResult>` - HTTP/HTTPS验证结果
- `dns_records: Option<DnsResolveResult>` - DNS记录解析结果

**`SubdomainScanData`** - 从 `SubdomainResult` 派生出的汇总视图
- `raw_results: Vec<SubdomainResult>` - 保真原始扫描结果，适合 JSON 导出
- `discovered_domains: Vec<DiscoveredDomain>` - 可展示/导出的发现结果
- `aggregated_domains: Vec<AggregatedDiscoveredDomain>` - 按域名聚合后的展示结果
- `verification_results: Vec<VerificationResult>` - HTTP/HTTPS验证结果列表
- `summary: SummaryStats` - 汇总统计

#### 主要函数

**`brute_force_subdomains()`** - 便捷的暴破函数
```rust
pub async fn brute_force_subdomains(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>>
```

**`run_speed_test()`** - 网速测试函数
```rust
pub async fn run_speed_test(duration_secs: u64) -> Result<(), Box<dyn std::error::Error>>
```

**`export_results()`** - 结果导出函数
```rust
pub fn export_results(
    raw_results: Vec<SubdomainResult>,
    discovered: Vec<DiscoveredDomain>,
    aggregated: Vec<AggregatedDiscoveredDomain>,
    verified: Vec<VerificationResult>,
    summary: SummaryStats,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>>
```

**`export_subdomain_results()`** - 直接导出扫描结果
```rust
pub fn export_subdomain_results(
    results: &[SubdomainResult],
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>>
```

JSON 导出会额外包含：
- `raw_results`：每条原始扫描记录，包含 `query_type`
- `aggregated_domains`：按域名聚合后的展示视图
- `verified` / `dns_records`：在启用对应功能后保留详细结果

### 完整示例

查看 `examples/` 目录中的完整示例：
- `examples/quick_start.rs` - 快速入门示例
- `examples/library_usage.rs` - 完整功能示例

运行示例：
```bash
# 运行快速入门示例
cargo run --example quick_start

# 运行完整示例
cargo run --example library_usage
```

### 注意事项

1. **权限要求**: 库的高性能路径会直接访问链路层接口。Linux 通常需要管理员权限或等效能力；macOS 在未配置 BPF 设备权限时通常需要 `sudo`，安装 Wireshark 的 `ChmodBPF`/`chmodbpf` 并赋予当前用户访问权限后可直接以普通用户运行
2. **异步运行时**: 必须在tokio运行时中使用
3. **网络依赖**: 需要稳定的网络连接
4. **系统依赖**: Windows 需要 Npcap/WinPcap 兼容环境；Linux/macOS 主要依赖系统原生网络接口权限配置
5. **错误处理**: 建议使用`?`操作符或`match`进行错误处理

### 集成建议

- 在Web应用中，建议将暴破任务放在后台队列中执行
- 在桌面应用中，建议使用进度回调显示扫描进度
- 在服务中，建议添加速率限制和超时控制
- 建议缓存DNS解析结果以提高性能

## 许可证
MIT License



## 贡献
欢迎提交Issue和Pull Request！

## 免责声明
本工具仅用于授权的安全测试和学习研究。使用者需遵守相关法律法规，作者不承担任何滥用责任。
