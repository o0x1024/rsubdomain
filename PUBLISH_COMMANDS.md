# rsubdomain v1.2.14 发布命令

## 快速步骤

### 1. 登录 crates.io

```bash
cargo login <YOUR_API_TOKEN>
```

### 2. 发布前检查

```bash
cargo build
cargo test
cargo package --list --allow-dirty
cargo package --allow-dirty
```

### 3. 发布

```bash
cargo publish --allow-dirty --registry crates-io
```

### 4. 发布后检查

1. 访问 https://crates.io/crates/rsubdomain
2. 确认显示版本 `1.2.14`
3. 验证安装：`cargo install rsubdomain`

## 当前发布内容

- 版本号：`1.2.14`
- 默认 CLI 等待时间改为 `10` 秒
- 新增 `--dns-timeout` 和 `--transport`
- 默认仍走 `Ethernet`，`UDP` 仅作为显式可选参数
- 修复大字典扫描收尾阶段的栈溢出
- 重构超时管理为到期队列
- 引入解析器健康评分和动态 DNS 超时
- 优化 `raw-records` 输出和 Ethernet 接收路径

## 注意事项

1. 每个版本号只能发布一次。
2. 当前仓库是 dirty 状态，因此命令里保留 `--allow-dirty`。
3. 当前环境若无法解析 `index.crates.io`，需要在可联网环境下执行发布命令。
