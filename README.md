# uablock-rs

基于 Rust 开发的 SIP (Session Initiation Protocol) User-Agent 封禁工具，通过实时监控网络流量，自动识别并封禁恶意或未授权的 SIP 请求。

## 功能特性

- **实时流量监控**：使用 libpcap 实时捕获网络数据包
- **智能封禁**：基于 User-Agent 白名单机制，自动封禁未授权 IP
- **自动解封**：当白名单中的 UA 请求时，自动解封对应 IP
- **多端口监听**：支持同时监听多个端口（默认 5060）
- **全流量封禁**：封禁 IP 时会阻止该 IP 的所有流量，而非仅限特定端口
- **GeoIP 过滤**：可选功能，非中国 IP 直接封禁，无需验证 UA
- **安全可靠**：使用网络层真实 IP，不信任数据包内容，防止 IP 伪装
- **高性能**：Rust 语言实现，内存安全且性能优异

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

```bash
# 克隆项目
git clone https://github.com/your-username/uablock-rs.git
cd uablock-rs

# 编译
cargo build --release

# 可执行文件位于 target/release/uablock-rust
```

## 使用方法

### 命令行参数

```
用法: uablock-rust [选项]

选项:
  -i, --interface <接口>    网络接口名称 (默认: eth0)
  -p, --ports <端口列表>    监听端口，逗号分隔 (默认: 5060)
  -g, --geoip [数据库路径]  启用 GeoIP 过滤，非中国 IP 直接封禁
  -u, --ua                  启用 UA 过滤，UA 不在白名单中则封禁
  -h, --help                显示帮助信息
```

### 基本用法

```bash
# 使用默认配置（eth0 接口、5060 端口、启用 UA 过滤）
sudo ./target/release/uablock-rust

# 指定网络接口和端口
sudo ./target/release/uablock-rust -i eth0 -p 5060

# 多端口监听
sudo ./target/release/uablock-rust -i eth0 -p 5060,5080,5090

# 仅启用 GeoIP 过滤
sudo ./target/release/uablock-rust -i eth0 -g

# 指定 GeoIP 数据库路径
sudo ./target/release/uablock-rust -i eth0 -g /usr/share/GeoIP/GeoLite2-Country.mmdb

# 同时启用 GeoIP 和 UA 过滤
sudo ./target/release/uablock-rust -i eth0 -g -u
```

### 过滤模式说明

| 模式 | 命令 | 说明 |
|------|------|------|
| 仅 UA 过滤 | `-u` 或无参数 | 检查 User-Agent，不在白名单则封禁 |
| 仅 GeoIP 过滤 | `-g` | 非 CN IP 直接封禁 |
| 双重过滤 | `-g -u` | 先 GeoIP 过滤，再 UA 检查 |

### 环境变量

```bash
# 设置 UA 白名单（逗号分隔）
SIP_UA_WHITELIST="freeswitch,microsip,telephone,jssip" sudo ./target/release/uablock-rust

# 设置日志级别
RUST_LOG=info sudo ./target/release/uablock-rust
RUST_LOG=warn sudo ./target/release/uablock-rust
```

### GeoIP 数据库

GeoIP 过滤需要 MaxMind GeoLite2-Country.mmdb 数据库文件。

程序默认搜索路径：
- `/usr/share/GeoIP/GeoLite2-Country.mmdb`
- `/var/lib/GeoIP/GeoLite2-Country.mmdb`
- `/usr/local/share/GeoIP/GeoLite2-Country.mmdb`
- `./GeoLite2-Country.mmdb`
- `/etc/GeoLite2-Country.mmdb`

下载数据库：
1. 访问 [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 注册免费账号
2. 下载 GeoLite2 Country 数据库（mmdb 格式）

## 默认配置

### 默认白名单

- `freeswitch`
- `microsip`
- `telephone`
- `jssip`

### 默认值

| 参数 | 默认值 |
|------|--------|
| 网络接口 | `eth0` |
| 监听端口 | `5060` |
| 过滤模式 | UA 过滤 |

## 工作原理

1. **数据包捕获**：使用 libpcap 捕获指定端口的 UDP 数据包
2. **SIP 解析**：解析 SIP REGISTER 和 INVITE 请求，提取 User-Agent 字段
3. **GeoIP 检查**（可选）：判断 IP 是否属于中国
4. **白名单检查**：检查 User-Agent 是否在白名单中
5. **封禁/解封**：根据检查结果使用 iptables 执行封禁或解封操作

## 查看封禁状态

```bash
# 查看所有封禁规则
sudo iptables -L INPUT -n -v

# 查看特定 IP 的规则
sudo iptables -L INPUT -n -v | grep <IP地址>

# 测试规则是否存在
sudo iptables -C INPUT -s <IP地址> -j DROP
echo $?  # 0 表示存在
```

## 故障排除

### 无法打开网络接口

```bash
# 检查接口名称
ip addr

# 检查接口状态
ip link show <接口名>
```

### 没有捕获到数据包

```bash
# 使用 tcpdump 验证流量
sudo tcpdump -i eth0 udp port 5060
```

### 编译错误：找不到 libpcap

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

## 项目结构

```
uablock-rs/
├── src/
│   ├── main.rs              # 主程序入口
│   ├── packet_capture.rs    # 数据包捕获模块
│   ├── sip_parser.rs        # SIP 协议解析模块
│   ├── whitelist.rs         # 白名单管理模块
│   ├── iptables_manager.rs  # iptables 封禁管理模块
│   └── geoip.rs             # GeoIP 地理位置查询模块
├── Cargo.toml               # 项目配置和依赖
└── README.md                # 本文档
```

## 依赖库

- `pcap` - 数据包捕获
- `regex` - 正则表达式
- `log` / `env_logger` - 日志
- `maxminddb` - GeoIP 数据库读取
- `libc` - 系统调用（Unix）

## 许可证

MIT
