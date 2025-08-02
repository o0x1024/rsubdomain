# rsubdomain v1.2.3 发布说明

## 🚀 主要更新

### 新增功能
- **字典数组支持**: 新增 `dictionary` 参数，允许直接传入字典数组而不仅仅是文件路径
- **API 灵活性增强**: 提供了 `brute_force_subdomains_with_dict` 和 `brute_force_subdomains_with_config` 函数

### 重要修复
- **进程退出问题**: 修复了任务完成后程序无法正常退出的问题
- **资源清理**: 改进了全局状态变量的清理机制，避免进程挂起
- **内存管理**: 优化了 `Arc` 和 `Mutex` 的使用，防止资源泄漏

### 性能优化
- **状态管理**: 重构了状态管理机制，使用 `BruteForceState` 替代全局变量
- **线程安全**: 改进了多线程环境下的数据共享和同步

## 📋 API 变更

### 新增 API

```rust
// 使用字典数组的便捷函数
pub async fn brute_force_subdomains_with_dict(
    domains: Vec<String>,
    dictionary: Vec<String>,  // 新增：直接传入字典数组
    resolvers: Option<Vec<String>>,
    skip_wildcard: bool,
    bandwidth_limit: Option<String>,
    verify_mode: bool,
    resolve_records: bool,
    silent: bool,
    device: Option<String>,
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>>

// 完整配置的便捷函数
pub async fn brute_force_subdomains_with_config(
    domains: Vec<String>,
    dictionary_file: Option<String>,
    dictionary: Option<Vec<String>>,  // 新增：可选的字典数组
    // ... 其他参数
) -> Result<Vec<SubdomainResult>, Box<dyn std::error::Error>>
```

### 配置结构体更新

```rust
pub struct SubdomainBruteConfig {
    // 现有字段...
    pub dictionary_file: Option<String>,
    pub dictionary: Option<Vec<String>>,  // 新增：字典数组字段
    // 其他字段...
}
```

## 🔧 使用示例

### 使用字典数组

```rust
use rsubdomain::brute_force_subdomains_with_dict;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domains = vec!["example.com".to_string()];
    let dictionary = vec![
        "www".to_string(),
        "mail".to_string(),
        "ftp".to_string(),
        "admin".to_string(),
    ];
    
    let results = brute_force_subdomains_with_dict(
        domains,
        dictionary,  // 直接传入字典数组
        None,        // resolvers
        true,        // skip_wildcard
        None,        // bandwidth_limit
        false,       // verify_mode
        false,       // resolve_records
        false,       // silent
        None,        // device
    ).await?;
    
    println!("发现 {} 个子域名", results.len());
    Ok(())
}
```

### 使用完整配置

```rust
use rsubdomain::{SubdomainBruteConfig, SubdomainBruteEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SubdomainBruteConfig {
        domains: vec!["example.com".to_string()],
        dictionary: Some(vec!["www".to_string(), "mail".to_string()]),  // 使用字典数组
        dictionary_file: None,  // 不使用文件
        verify_mode: true,
        resolve_records: true,
        ..Default::default()
    };

    let engine = SubdomainBruteEngine::new(config).await?;
    let results = engine.run_brute_force().await?;
    
    println!("暴破完成，发现 {} 个子域名", results.len());
    Ok(())
}
```

## 🐛 修复的问题

1. **进程挂起问题**: 修复了任务完成后程序无法退出的问题
2. **资源泄漏**: 改进了网络资源和线程资源的清理
3. **状态管理**: 解决了全局状态变量导致的并发问题

## ⚠️ 注意事项

- 本版本保持了向后兼容性，现有代码无需修改
- 推荐使用新的字典数组功能以获得更好的性能
- 修复了进程退出问题，程序现在能够正常结束

## 📦 安装和升级

```bash
# 安装最新版本
cargo install rsubdomain

# 或在 Cargo.toml 中指定版本
[dependencies]
rsubdomain = "1.2.3"
```

## 🔗 相关链接

- [GitHub 仓库](https://github.com/o0x1024/rsubdomain)
- [crates.io 页面](https://crates.io/crates/rsubdomain)
- [文档](https://docs.rs/rsubdomain)

---

**发布时间**: 2024年
**版本**: v1.2.3
**兼容性**: 向后兼容 v1.2.x