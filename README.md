# XProxy Wizard - 旁路由部署向导

XProxy Wizard 是一个为 [XProxy](https://github.com/dnomd343/XProxy) 项目开发的交互式部署向导，旨在简化透明代理网关的部署过程。

## 项目背景

[XProxy](https://github.com/dnomd343/XProxy) 是一个基于 Xray-core 的透明代理项目，支持多种代理协议，可以作为旁路由为局域网设备提供透明代理服务。然而，XProxy 的部署涉及复杂的网络配置、Docker 容器管理、iptables 规则设置等技术细节，对普通用户来说门槛较高。

XProxy Wizard 通过提供友好的交互式界面，自动化处理以下复杂配置：
- Docker macvlan 网络创建和管理
- 网络参数自动检测和配置
- XProxy 配置文件生成
- IPv4/IPv6 透明代理规则设置
- DHCP 服务配置（可选）
- 代理服务器参数配置

只需回答几个简单的问题，即可完成原本需要手动编写配置文件和执行多条命令才能完成的部署工作。

## 核心功能

### 自动化部署
- 🚀 一键部署 XProxy Docker 容器
- 🔧 自动检测网络环境（IP、网关、网卡）
- 📦 自动创建 Docker macvlan 网络
- 🛠️ 自动生成 XProxy 所需的全部配置文件

### 网络配置
- 🌐 支持 IPv4/IPv6 双栈透明代理
- 🚫 可选禁用 IPv6 DNS 解析（避免 IPv6 配置问题）
- 📡 可选的 DHCP 服务器功能
- 🔀 自动配置 iptables/ip6tables 规则

### 代理支持
- 🎯 支持 Shadowsocks 协议配置
- 🎯 支持 VMess 协议配置（含 WebSocket/gRPC）
- 🎯 支持 VLESS/Trojan（自定义配置）
- 🎯 支持直连模式（用于测试）

### 用户体验
- 💾 配置自动保存，支持快速重新部署
- 🔄 重新部署时自动填充所有历史配置
- 🛡️ 清理旧部署时智能保留配置文件
- 📝 友好的交互式界面，带默认值提示

## 工作原理

XProxy Wizard 通过以下步骤实现自动化部署：

1. **环境检测**：自动识别服务器的网络配置
2. **用户交互**：通过简单的问答收集必要信息
3. **配置生成**：生成 XProxy 所需的各种配置文件
   - `/etc/xproxy/xproxy.yml` - 主配置文件
   - `/etc/xproxy/config/*.json` - Xray 配置文件
4. **网络创建**：创建 Docker macvlan 网络，使容器获得独立 IP
5. **容器部署**：拉取并启动 XProxy Docker 容器
6. **规则配置**：设置透明代理所需的 iptables 规则

## 快速开始

### 前置要求
- Linux 服务器（推荐 Debian/Ubuntu）
- Docker 环境
- root 权限
- 网卡支持混杂模式

### 一键部署命令
```bash
# 下载并运行向导
wget -O /usr/local/bin/xproxy-wizard https://your-release-url/xproxy-wizard
chmod +x /usr/local/bin/xproxy-wizard
xproxy-wizard
```

## 详细部署步骤

### 1. 准备工作

在部署机器上安装 Docker：
```bash
ssh root@192.168.1.98
curl -fsSL https://get.docker.com | sh
```

### 2. 复制程序到远程服务器

#### 方法A：复制编译好的程序
```bash
# 在本地编译
cd /home/linux/projects/breeze/xproxy-wizard
go build -o xproxy-wizard main.go

# 复制到远程服务器
scp xproxy-wizard root@192.168.1.98:/usr/local/bin/
ssh root@192.168.1.98 chmod +x /usr/local/bin/xproxy-wizard
```

#### 方法B：复制源码并在远程编译
```bash
# 复制源码
scp main.go root@192.168.1.98:/tmp/

# SSH 到远程服务器
ssh root@192.168.1.98

# 安装 Go（如果需要）
apt-get update && apt-get install -y golang-go

# 编译
cd /tmp
go build -o /usr/local/bin/xproxy-wizard main.go
chmod +x /usr/local/bin/xproxy-wizard
```

### 3. 运行向导

```bash
ssh root@192.168.1.98
sudo xproxy-wizard
```

## 使用说明

1. **首次运行**：向导会自动检测网络环境，您需要确认或修改：
   - 主机 IP 地址
   - 网关 IP 地址
   - 旁路由 IP 地址（建议使用 .2 结尾的地址）
   - 代理服务器配置
   - 是否启用 DHCP
   - 是否启用 IPv6
   - 是否禁用 IPv6 DNS 解析（推荐）

2. **重新配置**：
   - 程序会自动检测并加载上次的配置
   - 所有输入项都会显示默认值（包括代理服务器详细信息）
   - 直接按回车即可使用原配置
   - 清理旧部署时配置文件会被保留

3. **配置文件位置**：
   - XProxy 配置：`/etc/xproxy/`
   - 向导配置备份：`/etc/xproxy/wizard-config.json`
   
4. **IPv6 支持**：
   - 可选择启用 IPv6 透明代理
   - 支持禁用 IPv6 DNS 解析（推荐）
   - 自动配置 IPv6 路由规则

## 常用命令

```bash
# 查看容器状态
docker ps -a | grep xproxy

# 查看日志
docker logs -f xproxy

# 查看 Xray 错误日志
docker exec xproxy tail -f /xproxy/log/error.log

# 重启服务
docker restart xproxy

# 停止服务
docker stop xproxy

# 进入容器调试
docker exec -it xproxy sh

# 检查网络连接
docker exec xproxy netstat -tlnpu | grep -E '53|7288|7289'

# 查看配置文件
cat /etc/xproxy/wizard-config.json
```

## 客户端配置

### IPv4 配置
将客户端设备的：
- 网关地址设置为旁路由 IP（如 192.168.1.2）
- DNS 服务器设置为旁路由 IP（如 192.168.1.2）

或在主路由器的 DHCP 设置中修改默认网关和 DNS：
```bash
# OpenWrt 设置
uci add_list dhcp.lan.dhcp_option="3,192.168.1.2"  # 网关
uci add_list dhcp.lan.dhcp_option="6,192.168.1.2"  # DNS
uci commit dhcp
/etc/init.d/dnsmasq restart
```

### IPv6 配置（如果启用）
对于移动设备，在 OpenWrt 路由器上配置：
```bash
uci set dhcp.lan.ra='server'
uci set dhcp.lan.dhcpv6='server'
uci set dhcp.lan.ra_default='0'
uci add_list dhcp.lan.dns='240e:3bb:32aa:6870::2'
uci commit dhcp
/etc/init.d/odhcpd restart
```

## 故障排查

1. **容器无法启动**：检查 `/etc/xproxy/xproxy.yml` 配置文件格式
2. **网络不通**：确保网卡开启了混杂模式，检查 macvlan 网络配置
3. **代理失败**：检查代理服务器配置，查看 error.log
4. **配置未保存**：
   - 检查 `/etc/xproxy/wizard-config.json` 是否存在
   - 确保程序有写入权限
   - 查看是否显示"未能读取旧配置"的警告
5. **IPv6 不工作**：
   - 考虑启用"禁用 IPv6 DNS 解析"选项
   - 检查容器是否分配了 IPv6 地址
   - 验证 IPv6 路由规则是否正确

## 新功能说明

### v1.2 更新
- ✅ 支持配置文件完整保存和恢复
- ✅ 代理服务器详细配置（地址、端口、密码等）自动填充
- ✅ 清理旧部署时保留配置文件
- ✅ 添加 IPv6 DNS 禁用选项
- ✅ 改进的错误提示和调试信息

### 配置保存机制
- 首次运行后会保存所有配置到 `/etc/xproxy/wizard-config.json`
- 包含代理服务器的详细信息（密码以明文保存，请注意安全）
- 清理旧部署时自动备份和恢复配置文件
- 支持一路回车完成重新部署

## 注意事项

- 需要 root 权限运行
- 确保旁路由 IP 不与现有设备冲突
- 部署机器网卡需支持混杂模式
- 建议在测试环境先行验证
- 配置文件包含敏感信息，请妥善保管

## 项目关系说明

### XProxy Wizard 与 XProxy 的关系
- **XProxy Wizard** 是部署工具，负责自动化配置和部署
- **[XProxy](https://github.com/dnomd343/XProxy)** 是核心服务，提供实际的透明代理功能
- Wizard 生成的配置文件完全兼容 XProxy 的配置格式
- 部署完成后，XProxy 独立运行，无需 Wizard 参与

### 技术架构
```
XProxy Wizard (本项目)
    ↓ 生成配置
    ↓ 创建网络
    ↓ 启动容器
XProxy Docker 容器
    ├── Xray-core (代理核心)
    ├── iptables (流量劫持)
    ├── DNS 服务器
    └── DHCP 服务器（可选）
```

### 适用场景
- 家庭/小型办公室网络的透明代理部署
- 旁路由模式，不影响主路由器
- 需要为所有设备提供代理服务
- 希望简化部署流程的用户

## 相关链接

- XProxy 官方项目：https://github.com/dnomd343/XProxy
- XProxy 文档：https://github.com/dnomd343/XProxy/tree/master/docs
- Xray-core 项目：https://github.com/XTLS/Xray-core
- 问题反馈：请在本项目的 Issues 中提交