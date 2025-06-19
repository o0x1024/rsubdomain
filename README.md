## rsubdomain
基于Rust实现的高性能子域名暴破工具，实现原理参考 [ksubdomain](https://github.com/knownsec/ksubdomain)

## 为什么选择rsubdomain
- 🚀 **高性能**: 基于原始套接字的异步DNS查询，支持高并发
- 🔍 **功能丰富**: 支持子域名发现、HTTP/HTTPS验证、DNS记录解析
- 📊 **多格式输出**: 支持JSON、XML、CSV、TXT四种输出格式
- 🌐 **智能网络**: 自动检测网络设备，支持手动指定网络接口
- 📈 **网速测试**: 内置DNS包发送速度测试功能
- 🎯 **泛解析检测**: 智能识别并处理泛解析域名
- 📋 **实时统计**: 提供详细的汇总统计信息

## 安装要求
使用前需要安装libpcap或npcap：

### Linux/macOS
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

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

# 使用自定义字典文件
./rsubdomain -d example.com -f wordlist.txt

# 静默模式（只输出发现的域名）
./rsubdomain -d example.com --slient

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
```

### 高级用法
```bash
# 完整功能组合使用
./rsubdomain -d example.com -f wordlist.txt -v --resolve-records --summary -o results.json --format json -e eth0 -b 3M
```

## 命令行参数详解

| 参数 | 长参数 | 描述 | 默认值 |
|------|--------|------|--------|
| `-d` | `--domain` | 需要扫描的目标域名（可多个） | 必需 |
| `-l` | `--list-network` | 列出所有网络接口 | - |
| `-r` | `--resolvers` | DNS解析器路径 | 系统默认DNS |
| `-s` | `--slient` | 静默模式，只输出域名 | false |
| `-f` | `--file` | 自定义字典文件路径 | 内置字典 |
| `-w` | `--skip-wildcard` | 跳过泛解析域名检测 | true |
| `-n` | `--network-test` | 执行网速测试 | - |
| | `--target-ip` | 网速测试目标IP | 8.8.8.8 |
| `-b` | `--bandwidth` | 带宽限制 (K/M/G) | 3M |
| `-v` | `--verify` | HTTP/HTTPS验证模式 | - |
| | `--resolve-records` | 解析DNS记录 | - |
| `-e` | `--device` | 手动指定网络设备 | 自动检测 |
| `-o` | `--output` | 输出文件路径 | - |
| | `--format` | 输出格式 (json/xml/csv/txt) | json |
| | `--summary` | 显示汇总统计 | - |

## 输出示例

### 标准输出
```
域名                          IP地址          记录类型    时间戳
--------------------------------------------------------------------------------
www.example.com               93.184.216.34   A          14:23:45
mail.example.com              93.184.216.35   A          14:23:46
ftp.example.com               ftp.example.org CNAME      14:23:47
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
发现域名总数: 156
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

- **原始套接字**: 直接构造和解析DNS包
- **异步处理**: 基于Tokio的异步I/O
- **智能解析**: 正确解析各种DNS记录类型
- **网络检测**: 自动识别最佳网络接口
- **数据导出**: 支持多种结构化数据格式

## 注意事项

1. **权限要求**: 需要管理员/root权限运行（原始套接字）
2. **防火墙**: 确保DNS流量（UDP 53端口）未被阻止
3. **网络环境**: 建议在稳定的网络环境下使用
4. **目标限制**: 请合理使用，避免对目标造成压力
5. **法律合规**: 仅用于授权的安全测试

## 更新日志

### v1.2.0 (最新)
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
# 从本地路径
rsubdomain = { path = "/path/to/rsubdomain" }

# 或从Git仓库
rsubdomain = { git = "https://github.com/o0x1024/rsubdomain" }

# 异步运行时（必需）
tokio = { version = "1.0", features = ["full"] }
```

### 快速开始

```rust
use rsubdomain::{brute_force_subdomains, SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 方法1: 使用便捷函数（最简单）
    let domains = vec!["example.com".to_string()];
    let results = brute_force_subdomains(domains, None).await?;
    
    println!("发现 {} 个子域名", results.len());
    for result in results.iter().take(5) {
        println!("  {} -> {}", result.domain, result.ip);
    }
    
    Ok(())
}
```

### 高级配置

```rust
use rsubdomain::{SubdomainBruteConfig, SubdomainBruteEngine, OutputFormat, export_results};

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
        resolve_records: true,  // 启用DNS记录解析
        silent: false,
        device: None, // 自动检测网络设备
    };

    // 创建暴破引擎
    let engine = SubdomainBruteEngine::new(config).await?;
    
    // 执行暴破
    let results = engine.run_brute_force().await?;
    
    // 处理结果
    for result in &results {
        println!("域名: {}", result.domain);
        println!("  IP: {}", result.ip);
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
    
    Ok(())
}
```

### API 参考

#### 主要结构体

**`SubdomainBruteConfig`** - 暴破配置
- `domains: Vec<String>` - 目标域名列表
- `resolvers: Vec<String>` - DNS服务器列表
- `dictionary_file: Option<String>` - 字典文件路径
- `skip_wildcard: bool` - 是否跳过泛解析检测
- `bandwidth_limit: Option<String>` - 带宽限制
- `verify_mode: bool` - 是否启用HTTP/HTTPS验证
- `resolve_records: bool` - 是否解析DNS记录
- `silent: bool` - 静默模式
- `device: Option<String>` - 网络设备名称

**`SubdomainResult`** - 暴破结果
- `domain: String` - 发现的域名
- `ip: String` - 对应的IP地址
- `record_type: String` - DNS记录类型
- `verified: Option<VerifyResult>` - HTTP/HTTPS验证结果
- `dns_records: Option<DnsResolveResult>` - DNS记录解析结果

#### 主要函数

**`brute_force_subdomains()`** - 便捷的暴破函数
```rust
pub async fn brute_force_subdomains(
    domains: Vec<String>,
    dictionary_file: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>>
```

**`run_speed_test()`** - 网速测试函数
```rust
pub async fn run_speed_test(duration_secs: u64) -> Result<(), Box<dyn std::error::Error>>
```

**`export_results()`** - 结果导出函数
```rust
pub fn export_results(
    discovered: Vec<DiscoveredDomain>,
    verified: Vec<VerificationResult>,
    summary: SummaryStats,
    output_path: &str,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>>
```

### 完整示例

查看 `examples/` 目录中的完整示例：
- `examples/quick_start.rs` - 快速入门示例
- `examples/library_usage.rs` - 完整功能示例
- `examples/Cargo.toml` - 依赖配置示例

运行示例：
```bash
# 进入示例目录
cd examples

# 运行快速入门示例
cargo run --bin quick_start

# 运行完整示例
cargo run --bin library_usage
```

### 注意事项

1. **权限要求**: 库使用原始套接字，需要管理员权限
2. **异步运行时**: 必须在tokio运行时中使用
3. **网络依赖**: 需要稳定的网络连接
4. **系统依赖**: 需要安装libpcap/npcap
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
