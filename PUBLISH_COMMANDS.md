# rsubdomain v1.2.3 发布命令

## 🚀 快速发布步骤

### 1. 登录 crates.io

如果还没有登录，需要先获取 API Token：

1. 访问 https://crates.io/
2. 使用 GitHub 账号登录
3. 进入 Account Settings
4. 生成新的 API Token
5. 复制 Token 并执行：

```bash
cargo login <YOUR_API_TOKEN>
```

### 2. 最终检查

```bash
# 清理构建缓存
cargo clean

# 编译检查
cargo check

# 运行测试
cargo test

# 检查包内容
cargo package --list --allow-dirty

# 创建发布包
cargo package --allow-dirty
```

### 3. 发布到 crates.io

由于使用了代理注册表，需要指定官方注册表：

```bash
# 发布命令（指定官方注册表）
cargo publish --allow-dirty --registry crates-io
```

### 4. 验证发布

发布成功后：

1. 访问 https://crates.io/crates/rsubdomain
2. 检查版本 1.2.3 是否显示
3. 测试安装：`cargo install rsubdomain`

## 📋 当前状态

- ✅ 版本号已更新为 1.2.3
- ✅ 代码编译通过（有警告但无错误）
- ✅ 所有测试通过（4个单元测试 + 2个文档测试）
- ✅ 发布包创建成功
- ✅ 发布文档已更新

## 🔧 本次更新内容

- **新增**: 支持传入字典数组 (`dictionary` 参数)
- **修复**: 任务完成后程序无法正常退出的问题
- **改进**: 增强了 API 的灵活性和稳定性
- **优化**: 资源清理机制，避免进程挂起

## ⚠️ 注意事项

1. **注册表问题**: 由于使用了代理注册表，必须添加 `--registry crates-io` 参数
2. **Git 状态**: 使用 `--allow-dirty` 因为有未提交的更改
3. **版本唯一性**: 1.2.3 版本号只能发布一次，如果失败需要递增版本号

## 🚨 如果发布失败

常见问题和解决方案：

1. **版本已存在**: 递增版本号到 1.2.4
2. **权限问题**: 检查 API Token 是否正确
3. **网络问题**: 检查网络连接和代理设置
4. **依赖问题**: 确保所有依赖都是稳定版本

---

**准备就绪**: 所有检查已完成，可以执行发布命令 ✅