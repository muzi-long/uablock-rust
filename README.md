# SIP UA 封禁工具 (uablock-rust)

一个基于 Rust 开发的 SIP (Session Initiation Protocol) User-Agent 封禁工具，通过实时监控网络流量，自动识别并封禁恶意或未授权的 SIP 请求。

## 功能特性

- 🔍 **实时流量监控**：使用 libpcap 实时捕获网络数据包
- 🛡️ **智能封禁**：基于 User-Agent 白名单机制，自动封禁未授权 IP
- 🔓 **自动解封**：当白名单中的 UA 请求时，自动解封对应 IP
- 🎯 **精确端口控制**：支持指定封禁端口（默认 5060，SIP 标准端口）
- 🔒 **安全可靠**：使用网络层真实 IP，不信任数据包内容，防止 IP 伪装
- 📊 **详细日志**：提供完整的操作日志，便于调试和审计
- ⚡ **高性能**：Rust 语言实现，内存安全且性能优异

## 系统要求

- **操作系统**：Linux (Ubuntu/Debian/CentOS 等)
- **权限**：需要 root 权限（用于 iptables 操作和数据包捕获）
- **依赖库**：
  - `libpcap-dev` - 数据包捕获库
  - `iptables` - 防火墙工具

## 安装依赖

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y libpcap-dev build-essential
```

### CentOS/RHEL

```bash
sudo yum install -y libpcap-devel gcc
```

## 编译

### 本地编译

```bash
# 克隆项目
git clone <repository-url>
cd uablock-rust

# 编译
cargo build --release

# 可执行文件位于 target/release/uablock-rust
```

### 交叉编译（macOS → Linux）

如果需要从 macOS 编译 Linux 版本，可以使用 `cross` 工具：

```bash
# 安装 cross
cargo install cross --git https://github.com/cross-rs/cross

# 编译 Linux 版本
cross build --release --target x86_64-unknown-linux-gnu

# 可执行文件位于 target/x86_64-unknown-linux-gnu/release/uablock-rust
```

## 使用方法

### 基本用法

```bash
# 使用默认网络接口 (eth0) 和默认端口 (5060)
sudo ./target/release/uablock-rust

# 指定网络接口
sudo ./target/release/uablock-rust eth0

# 指定网络接口和封禁端口
sudo ./target/release/uablock-rust eth0 5060
```

### 参数说明

1. **网络接口**（第一个参数，可选）
   - 默认值：`eth0`
   - 示例：`eth0`, `ens33`, `enp0s3` 等
   - 查看可用接口：程序启动失败时会自动列出

2. **封禁端口**（第二个参数，可选）
   - 默认值：`5060` (SIP 标准端口)
   - 示例：`5060`, `5080` 等
   - 封禁时只会阻止该 IP 访问指定端口，其他端口不受影响

### 环境变量

#### 日志级别

```bash
# 设置日志级别（默认 DEBUG）
RUST_LOG=info sudo ./target/release/uablock-rust
RUST_LOG=warn sudo ./target/release/uablock-rust
RUST_LOG=error sudo ./target/release/uablock-rust
```

#### 白名单配置

```bash
# 通过环境变量设置白名单（逗号分隔）
SIP_UA_WHITELIST="friendly-scanner,sipcli,asterisk,freeswitch" sudo ./target/release/uablock-rust
```

## 工作原理

### 1. 数据包捕获

- 使用 libpcap 在指定网络接口上捕获 UDP 数据包
- 自动检测并跳过以太网头，提取 IP 层数据
- 从 IP 头提取**网络层真实源 IP**（不可伪装）

### 2. SIP 请求解析

- 解析 UDP 数据包内容，识别 SIP REGISTER 和 INVITE 请求
- 提取 User-Agent 字段
- 只处理 REGISTER 和 INVITE 请求，其他 SIP 方法忽略

### 3. 白名单检查

- 检查 User-Agent 是否在白名单中（支持模糊匹配）
- 默认白名单包含：`friendly-scanner`, `sipcli`, `asterisk`, `freeswitch`, `linphone`, `microsip`

### 4. 封禁/解封逻辑

- **封禁**：如果 UA 不在白名单中，使用 iptables 封禁该 IP 访问指定端口
- **解封**：如果 UA 在白名单中但 IP 已被封禁，自动解封

### 5. 安全特性

- ✅ 使用网络层真实 IP，不信任数据包内容（如 Via 头中的 IP）
- ✅ 只封禁指定端口，不影响其他服务
- ✅ 自动检测已封禁状态，避免重复封禁

## 配置说明

### 默认白名单

程序内置以下默认白名单模式：

- `friendly-scanner`
- `sipcli`
- `asterisk`
- `freeswitch`
- `linphone`
- `microsip`

### 自定义白名单

#### 方法 1：环境变量

```bash
export SIP_UA_WHITELIST="your-ua1,your-ua2,your-ua3"
sudo ./target/release/uablock-rust
```

#### 方法 2：修改代码

编辑 `src/main.rs` 中的 `initialize_whitelist()` 函数。

### 白名单匹配规则

- 支持模糊匹配（不区分大小写）
- 如果模式包含在 UA 中，或 UA 包含在模式中，则匹配成功
- 示例：模式 `asterisk` 可以匹配 `Asterisk/18.0.0`

## 日志说明

### 日志级别

- **DEBUG**：详细的调试信息（默认）
- **INFO**：重要操作信息（封禁/解封成功）
- **WARN**：警告信息（封禁操作）
- **ERROR**：错误信息（操作失败）

### 日志示例

```
[INFO] SIP UA 封禁工具启动
[INFO] 使用网络接口: eth0
[INFO] 封禁端口: 5060
[INFO] 白名单模式: ["friendly-scanner", "sipcli", "asterisk", ...]
[INFO] 开始监控 SIP 流量...
[INFO] 收到 SIP REGISTER 请求，来源 IP: 118.113.6.164（网络层真实IP），User-Agent: Telephone 1.6
[WARN] 【封禁】User-Agent: 'Telephone 1.6', IP: 118.113.6.164, 原因: UA 不在白名单中
[INFO] 【封禁成功】User-Agent: 'Telephone 1.6', IP: 118.113.6.164
[INFO] 【确认封禁】User-Agent: 'Telephone 1.6', IP: 118.113.6.164 已被成功封禁
```

## 查看封禁状态

### 查看 iptables 规则

```bash
# 查看所有封禁规则
sudo iptables -L INPUT -n -v

# 查看特定 IP 的规则
sudo iptables -L INPUT -n -v | grep <IP地址>

# 查看数字格式的端口（显示 5060 而不是 sip）
sudo iptables -L INPUT -n -v
```

### 手动测试封禁

```bash
# 测试规则是否存在
sudo iptables -C INPUT -s <IP地址> -p udp --dport 5060 -j DROP
echo $?  # 0 表示规则存在，非 0 表示不存在
```

## 故障排除

### 1. 无法打开网络接口

**错误**：`无法打开网络接口: ...`

**解决方案**：
- 检查接口名称是否正确：`ip addr` 或 `ifconfig`
- 确保有 root 权限
- 检查接口是否处于 UP 状态

### 2. 没有捕获到数据包

**可能原因**：
- 网络接口选择错误
- 没有 SIP 流量经过该接口
- 数据包被其他程序处理

**解决方案**：
- 使用 `tcpdump` 验证接口是否有流量：`sudo tcpdump -i eth0 udp port 5060`
- 检查程序日志，确认是否解析到 SIP 请求

### 3. 封禁规则未生效

**可能原因**：
- iptables 规则被其他规则覆盖
- 规则顺序问题

**解决方案**：
- 检查 iptables 规则顺序：`sudo iptables -L INPUT -n --line-numbers`
- 查看程序日志中的警告信息
- 手动验证规则：`sudo iptables -C INPUT -s <IP> -p udp --dport 5060 -j DROP`

### 4. 编译错误：找不到 libpcap

**错误**：`error: linking with 'cc' failed: exit status: 1 ... unable to find library -lpcap`

**解决方案**：
```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

## 注意事项

1. **权限要求**：程序必须使用 root 权限运行（sudo）
2. **网络接口**：确保选择正确的网络接口，否则无法捕获流量
3. **iptables 规则**：程序添加的规则是临时的，重启后会丢失
4. **性能影响**：程序会持续监控网络流量，对系统性能影响很小
5. **端口封禁**：只封禁指定端口，不会影响其他服务
6. **白名单管理**：建议根据实际环境配置合适的白名单

## 项目结构

```
uablock-rust/
├── src/
│   ├── main.rs              # 主程序入口
│   ├── packet_capture.rs    # 数据包捕获模块
│   ├── sip_parser.rs        # SIP 协议解析模块
│   ├── whitelist.rs         # 白名单管理模块
│   └── iptables_manager.rs  # iptables 封禁管理模块
├── Cargo.toml               # 项目配置和依赖
└── README.md                # 本文档
```

## 依赖库

- `pcap` - 数据包捕获库
- `regex` - 正则表达式库（用于 SIP 解析）
- `log` / `env_logger` - 日志库
- `libc` - 系统调用库（Unix 平台）

## 开发

### 运行测试

```bash
cargo test
```

### 代码检查

```bash
cargo check
cargo clippy
```

### 格式化代码

```bash
cargo fmt
```

## 许可证

[根据项目实际情况填写]

## 贡献

欢迎提交 Issue 和 Pull Request！

## 作者

[根据项目实际情况填写]

