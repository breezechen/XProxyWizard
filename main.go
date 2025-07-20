package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Config 结构体定义配置信息
type Config struct {
	HostIP      string      `json:"host_ip"`
	GatewayIP   string      `json:"gateway_ip"`
	Interface   string      `json:"interface"`
	ProxyIP     string      `json:"proxy_ip"`
	ProxyType   string      `json:"proxy_type"`
	ProxyConfig ProxyConfig `json:"-"` // 不保存具体代理配置
	EnableDHCP  bool        `json:"enable_dhcp"`
	DHCPStart   string      `json:"dhcp_start"`
	DHCPEnd     string      `json:"dhcp_end"`
	EnableIPv6     bool        `json:"enable_ipv6"`
	IPv6Prefix     string      `json:"ipv6_prefix"`
	IPv6Gateway    string      `json:"ipv6_gateway"`
	DisableIPv6DNS bool        `json:"disable_ipv6_dns"`
	MacvlanName    string      `json:"macvlan_name"`  // 新增：macvlan 网络名称
	
	// 保存代理服务器配置用于下次默认值
	ProxyServer    string `json:"proxy_server,omitempty"`
	ProxyPort      int    `json:"proxy_port,omitempty"`
	ProxyPassword  string `json:"proxy_password,omitempty"`
	ProxyMethod    string `json:"proxy_method,omitempty"`
	ProxyUUID      string `json:"proxy_uuid,omitempty"`
	ProxyAlterId   int    `json:"proxy_alterid,omitempty"`
	ProxyNetwork   string `json:"proxy_network,omitempty"`
	ProxyPath      string `json:"proxy_path,omitempty"`
	ProxyTLS       bool   `json:"proxy_tls,omitempty"`
}

// ProxyConfig 代理配置接口
type ProxyConfig interface {
	GenerateJSON() string
}

// ShadowsocksConfig SS配置
type ShadowsocksConfig struct {
	Server   string
	Port     int
	Password string
	Method   string
}

// VMeSSConfig VMess配置
type VMeSSConfig struct {
	Server  string
	Port    int
	UUID    string
	AlterId int
	Network string
	Path    string
	TLS     bool
}

// 颜色输出
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorReset  = "\033[0m"
	
	ConfigFile = "/etc/xproxy/wizard-config.json"
)

func main() {
	fmt.Println(ColorBlue + `
╔═══════════════════════════════════════════╗
║        XProxy 部署向导 v1.1               ║
║   简化您的透明代理网关部署流程            ║
╚═══════════════════════════════════════════╝` + ColorReset)
	fmt.Println()

	// 检查 Docker
	if !checkDocker() {
		printError("未检测到 Docker 环境，请先安装 Docker")
		os.Exit(1)
	}
	printSuccess("✓ Docker 环境检测通过")

	// 检查是否以 root 权限运行
	if os.Geteuid() != 0 {
		printWarning("建议使用 sudo 权限运行此程序")
	}

	config := &Config{}
	reader := bufio.NewReader(os.Stdin)
	
	// 尝试加载旧配置
	var oldConfig *Config
	if checkExistingDeployment() {
		// 尝试读取旧配置
		if cfg, err := loadConfig(); err == nil {
			oldConfig = cfg
			fmt.Println("\n" + ColorGreen + "✓ 成功读取旧配置" + ColorReset)
		} else {
			fmt.Printf("\n" + ColorYellow + "⚠ 未能读取旧配置: %v" + ColorReset + "\n", err)
		}
		
		fmt.Println("\n" + ColorYellow + "检测到已存在的 XProxy 部署" + ColorReset)
		if askYesNo(reader, "是否清理旧部署并重新安装？") {
			if err := cleanupOldDeployment(); err != nil {
				printError("清理失败: " + err.Error())
				os.Exit(1)
			}
			printSuccess("✓ 旧部署已清理")
		} else {
			fmt.Println("部署已取消")
			os.Exit(0)
		}
	}

	// 获取网络信息
	fmt.Println("\n" + ColorYellow + "【步骤1】检测网络环境" + ColorReset)
	if err := detectNetwork(config); err != nil {
		printError("网络检测失败: " + err.Error())
		os.Exit(1)
	}
	
	// 如果有旧配置，使用旧配置的值作为默认值（如果当前检测失败或用户想覆盖）
	if oldConfig != nil && oldConfig.HostIP != "" && config.HostIP == "" {
		config.HostIP = oldConfig.HostIP
		config.GatewayIP = oldConfig.GatewayIP
		config.Interface = oldConfig.Interface
	}

	// 显示检测结果
	fmt.Printf("\n检测到的网络信息：\n")
	fmt.Printf("  主机 IP: %s\n", ColorGreen+config.HostIP+ColorReset)
	fmt.Printf("  网关 IP: %s\n", ColorGreen+config.GatewayIP+ColorReset)
	fmt.Printf("  网络接口: %s\n", ColorGreen+config.Interface+ColorReset)

	// 配置旁路由 IP
	fmt.Println("\n" + ColorYellow + "【步骤2】配置旁路由网络" + ColorReset)
	defaultProxyIP := ""
	if oldConfig != nil {
		defaultProxyIP = oldConfig.ProxyIP
	}
	config.ProxyIP = askProxyIP(reader, config.HostIP, defaultProxyIP)

	// 选择代理类型
	fmt.Println("\n" + ColorYellow + "【步骤3】配置代理服务器" + ColorReset)
	configureProxy(reader, config, oldConfig)

	// 询问是否启用 DHCP
	fmt.Println("\n" + ColorYellow + "【步骤4】DHCP 服务配置（可选）" + ColorReset)
	enableDHCP := false
	if oldConfig != nil {
		enableDHCP = oldConfig.EnableDHCP
	}
	if askYesNoWithDefault(reader, "是否需要 XProxy 提供 DHCP 服务？", enableDHCP) {
		configureDHCP(reader, config, oldConfig)
	}

	// 询问是否启用 IPv6
	fmt.Println("\n" + ColorYellow + "【步骤5】IPv6 支持配置" + ColorReset)
	enableIPv6 := false
	if oldConfig != nil {
		enableIPv6 = oldConfig.EnableIPv6
	}
	config.EnableIPv6 = askYesNoWithDefault(reader, "是否启用 IPv6 透明代理支持？", enableIPv6)
	if config.EnableIPv6 {
		// 检测 IPv6 网络
		if err := detectIPv6Network(config); err != nil {
			printWarning("无法自动检测 IPv6 网络: " + err.Error())
			config.EnableIPv6 = false
			fmt.Println(ColorYellow + "⚠ IPv6 检测失败，将仅使用 IPv4" + ColorReset)
		} else {
			fmt.Println(ColorGreen + "✓ 检测到 IPv6 网络" + ColorReset)
			if config.IPv6Prefix != "" {
				fmt.Printf("  IPv6 前缀: %s\n", config.IPv6Prefix)
			}
			if config.IPv6Gateway != "" {
				fmt.Printf("  IPv6 网关: %s\n", config.IPv6Gateway)
			}
		}
	} else {
		fmt.Println(ColorYellow + "⚠ IPv6 支持已禁用，仅使用 IPv4" + ColorReset)
	}
	
	// 询问是否禁用 IPv6 DNS 解析
	fmt.Println("\n" + ColorYellow + "【DNS 配置】" + ColorReset)
	disableIPv6DNS := true  // 默认推荐禁用
	if oldConfig != nil {
		disableIPv6DNS = oldConfig.DisableIPv6DNS
	}
	config.DisableIPv6DNS = askYesNoWithDefault(reader, "是否禁用 IPv6 DNS 解析？（推荐：可以避免 IPv6 配置问题）", disableIPv6DNS)
	if config.DisableIPv6DNS {
		fmt.Println(ColorGreen + "✓ 将只解析 IPv4 地址，所有流量通过 IPv4 代理" + ColorReset)
	}

	// 确认配置
	fmt.Println("\n" + ColorYellow + "【步骤6】确认配置信息" + ColorReset)
	displayConfig(config)

	if !askYesNo(reader, "\n以上配置是否正确？") {
		fmt.Println("部署已取消")
		os.Exit(0)
	}

	// 开始部署
	fmt.Println("\n" + ColorYellow + "【步骤7】开始部署 XProxy" + ColorReset)
	if err := deployXProxy(config); err != nil {
		printError("部署失败: " + err.Error())
		// 尝试清理失败的部署
		cleanupOldDeployment()
		os.Exit(1)
	}

	// 验证部署
	fmt.Println("\n" + ColorYellow + "【步骤8】验证部署" + ColorReset)
	if err := verifyDeployment(config); err != nil {
		printWarning("部署验证失败: " + err.Error())
		fmt.Println("请手动检查容器状态和日志")
	} else {
		printSuccess("✓ 部署验证通过")
	}

	// 保存配置以供下次使用
	if err := saveConfig(config); err != nil {
		printWarning("无法保存配置: " + err.Error())
	}
	
	printSuccess("\n✓ XProxy 部署完成！")
	fmt.Printf("\n旁路由 IP 地址: %s%s%s\n", ColorGreen, config.ProxyIP, ColorReset)
	fmt.Println("\n客户端配置方法：")
	fmt.Println("1. 将设备的网关地址设置为:", ColorGreen+config.ProxyIP+ColorReset)
	fmt.Println("2. 将设备的 DNS 服务器设置为:", ColorGreen+config.ProxyIP+ColorReset)
	fmt.Println("3. 或在路由器 DHCP 设置中将默认网关和 DNS 都改为:", ColorGreen+config.ProxyIP+ColorReset)

	fmt.Println("\n常用命令：")
	fmt.Println("  查看日志: sudo docker logs -f xproxy")
	fmt.Println("  查看 Xray 日志: sudo docker exec xproxy tail -f /xproxy/log/error.log")
	fmt.Println("  重启服务: sudo docker restart xproxy")
	fmt.Println("  停止服务: sudo docker stop xproxy")
	fmt.Println("  诊断问题: sudo docker exec xproxy netstat -tlnpu | grep -E '53|7288|7289'")
}

// checkExistingDeployment 检查是否存在旧部署
func checkExistingDeployment() bool {
	// 检查容器
	cmd := exec.Command("docker", "ps", "-a", "--filter", "name=xproxy", "-q")
	output, _ := cmd.Output()
	if len(output) > 0 {
		return true
	}

	// 检查配置目录
	if _, err := os.Stat("/etc/xproxy"); err == nil {
		return true
	}

	// 检查是否有 macvlan 类型的网络
	cmd = exec.Command("docker", "network", "ls", "--filter", "driver=macvlan", "-q")
	output, _ = cmd.Output()
	return len(output) > 0
}

// cleanupOldDeployment 清理旧部署
func cleanupOldDeployment() error {
	fmt.Println("\n开始清理旧部署...")

	// 1. 停止并删除容器
	fmt.Println("停止容器...")
	exec.Command("docker", "stop", "xproxy").Run()
	exec.Command("docker", "rm", "xproxy").Run()

	// 2. 不删除网络，因为可能被其他容器使用
	// 如果需要删除，用户可以手动执行 docker network rm

	// 3. 清理配置文件（保留wizard-config.json）
	fmt.Println("清理配置文件...")
	// 保存wizard配置文件
	wizardConfigData, _ := os.ReadFile("/etc/xproxy/wizard-config.json")
	
	// 删除整个目录
	os.RemoveAll("/etc/xproxy")
	
	// 恢复wizard配置文件
	if len(wizardConfigData) > 0 {
		os.MkdirAll("/etc/xproxy", 0755)
		os.WriteFile("/etc/xproxy/wizard-config.json", wizardConfigData, 0644)
	}

	return nil
}

// checkDocker 检查 Docker 是否安装
func checkDocker() bool {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	return err == nil
}

// detectNetwork 自动检测网络信息
func detectNetwork(config *Config) error {
	// 获取默认路由信息
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("无法获取路由信息")
	}

	// 解析网关和接口
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default via") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				config.GatewayIP = parts[2]
				config.Interface = parts[4]
				break
			}
		}
	}

	if config.GatewayIP == "" {
		return fmt.Errorf("无法检测到默认网关")
	}

	// 获取接口 IP
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return fmt.Errorf("无法获取网络接口信息")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("无法获取 IP 地址")
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				config.HostIP = ipnet.IP.String()
				break
			}
		}
	}

	return nil
}

// generateIPv6Address 基于前缀生成一个 IPv6 地址
func generateIPv6Address(prefix string) string {
	// 从前缀生成一个地址，例如：2409:8a55:e2a7:3a0::/64 -> 2409:8a55:e2a7:3a0::2/64
	if strings.Contains(prefix, "/") {
		parts := strings.Split(prefix, "/")
		if len(parts) == 2 {
			// 移除尾部的 :: 并添加 ::2
			base := strings.TrimSuffix(parts[0], "::")
			return base + "::2/" + parts[1]
		}
	}
	return ""
}

// detectIPv6Network 检测 IPv6 网络信息
func detectIPv6Network(config *Config) error {
	// 获取 IPv6 路由信息
	cmd := exec.Command("ip", "-6", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("无法获取 IPv6 路由信息")
	}

	// 解析 IPv6 网关
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default via") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				config.IPv6Gateway = parts[2]
				break
			}
		}
	}

	// 获取接口的 IPv6 地址和前缀
	if config.Interface != "" {
		cmd = exec.Command("ip", "-6", "addr", "show", "dev", config.Interface)
		output, err = cmd.Output()
		if err == nil {
			lines = strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "inet6") && !strings.Contains(line, "fe80") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						// 解析出前缀（例如：2409:8a55:e2a7:3a0::/64）
						addr := parts[1]
						if strings.Contains(addr, "/") {
							addrParts := strings.Split(addr, "/")
							if len(addrParts) == 2 {
								// 提取网络前缀
								ip := net.ParseIP(addrParts[0])
								if ip != nil && ip.To16() != nil {
									prefixLen, _ := strconv.Atoi(addrParts[1])
									// 计算网络前缀
									mask := net.CIDRMask(prefixLen, 128)
									network := ip.Mask(mask)
									config.IPv6Prefix = fmt.Sprintf("%s/%d", network.String(), prefixLen)
								}
							}
						}
						break
					}
				}
			}
		}
	}

	return nil
}

// askProxyIP 询问旁路由 IP
func askProxyIP(reader *bufio.Reader, hostIP string, defaultIP string) string {
	// 生成建议的 IP
	parts := strings.Split(hostIP, ".")
	if len(parts) == 4 {
		// 查找可用的 IP 地址
		fmt.Println("正在查找可用的 IP 地址...")
		suggestedIP := findAvailableIP(parts[0], parts[1], parts[2], defaultIP)
		
		for {
			fmt.Printf("\n请输入旁路由 IP 地址 [默认: %s]: ", suggestedIP)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			if input == "" {
				input = suggestedIP
			}

			if !isValidIP(input) {
				printError("无效的 IP 地址")
				continue
			}

			// 检查 IP 是否已被占用
			if isIPInUse(input) {
				printWarning(fmt.Sprintf("IP 地址 %s 已被占用", input))
				
				// 显示占用信息
				showIPUsageInfo(input)
				
				fmt.Println("\n请选择其他 IP 地址，或停止占用该 IP 的服务")
				
				// 如果默认 IP 被占用，尝试建议下一个可用的
				if input == suggestedIP {
					newSuggested := findNextAvailableIP(parts[0], parts[1], parts[2], input)
					if newSuggested != input {
						suggestedIP = newSuggested
						fmt.Printf("建议使用: %s\n", suggestedIP)
					}
				}
				continue
			}

			return input
		}
	}

	// 如果无法生成建议，要求用户输入
	for {
		fmt.Print("\n请输入旁路由 IP 地址: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if !isValidIP(input) {
			printError("请输入有效的 IP 地址")
			continue
		}

		if isIPInUse(input) {
			printWarning(fmt.Sprintf("IP 地址 %s 已被占用", input))
			showIPUsageInfo(input)
			fmt.Println("请选择其他地址")
			continue
		}

		return input
	}
}

// configureProxy 配置代理
func configureProxy(reader *bufio.Reader, config *Config, oldConfig *Config) {
	// 显示旧配置信息
	defaultChoice := ""
	oldProxyType := ""
	if oldConfig != nil {
		oldProxyType = oldConfig.ProxyType
	}
	if oldProxyType != "" {
		fmt.Printf("\n当前配置的代理类型: %s%s%s\n", ColorGreen, oldProxyType, ColorReset)
		switch oldProxyType {
		case "shadowsocks":
			defaultChoice = "1"
		case "vmess":
			defaultChoice = "2"
		case "freedom":
			defaultChoice = "5"
		default:
			defaultChoice = "3"
		}
	}
	
	fmt.Println("\n请选择代理类型：")
	fmt.Println("1. Shadowsocks")
	fmt.Println("2. VMess")
	fmt.Println("3. VLESS (需手动配置)")
	fmt.Println("4. Trojan (需手动配置)")
	fmt.Println("5. 直连模式（测试用）")

	defaultPrompt := ""
	if defaultChoice != "" {
		defaultPrompt = fmt.Sprintf(" [默认: %s]", defaultChoice)
	}
	fmt.Printf("\n请输入选项 [1-5]%s: ", defaultPrompt)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	
	// 如果用户直接回车，使用默认值
	if choice == "" && defaultChoice != "" {
		choice = defaultChoice
	}

	switch choice {
	case "1":
		config.ProxyType = "shadowsocks"
		ssConfig := configureShadowsocks(reader, oldConfig)
		config.ProxyConfig = ssConfig
		// 保存到主配置以供下次使用
		config.ProxyServer = ssConfig.Server
		config.ProxyPort = ssConfig.Port
		config.ProxyPassword = ssConfig.Password
		config.ProxyMethod = ssConfig.Method
	case "2":
		config.ProxyType = "vmess"
		vmConfig := configureVMess(reader, oldConfig)
		config.ProxyConfig = vmConfig
		// 保存到主配置以供下次使用
		config.ProxyServer = vmConfig.Server
		config.ProxyPort = vmConfig.Port
		config.ProxyUUID = vmConfig.UUID
		config.ProxyAlterId = vmConfig.AlterId
		config.ProxyNetwork = vmConfig.Network
		config.ProxyPath = vmConfig.Path
		config.ProxyTLS = vmConfig.TLS
	case "5":
		config.ProxyType = "freedom"
		fmt.Println(ColorYellow + "\n将使用直连模式，仅用于测试透明代理功能" + ColorReset)
	default:
		config.ProxyType = "custom"
		fmt.Println(ColorYellow + "\n将使用自定义配置，请在部署后手动编辑 /etc/xproxy/config/outbounds.json" + ColorReset)
	}
}

// configureShadowsocks 配置 SS
func configureShadowsocks(reader *bufio.Reader, oldConfig *Config) *ShadowsocksConfig {
	config := &ShadowsocksConfig{Method: "aes-256-gcm"}
	
	// 设置默认值
	defaultServer := ""
	defaultPort := 8388
	defaultPassword := ""
	defaultMethod := "aes-256-gcm"
	
	if oldConfig != nil && oldConfig.ProxyType == "shadowsocks" {
		if oldConfig.ProxyServer != "" {
			defaultServer = oldConfig.ProxyServer
		}
		if oldConfig.ProxyPort > 0 {
			defaultPort = oldConfig.ProxyPort
		}
		if oldConfig.ProxyPassword != "" {
			defaultPassword = oldConfig.ProxyPassword
		}
		if oldConfig.ProxyMethod != "" {
			defaultMethod = oldConfig.ProxyMethod
		}
	}

	// 服务器地址
	if defaultServer != "" {
		fmt.Printf("\n服务器地址 [默认: %s]: ", defaultServer)
	} else {
		fmt.Print("\n服务器地址: ")
	}
	config.Server, _ = reader.ReadString('\n')
	config.Server = strings.TrimSpace(config.Server)
	if config.Server == "" && defaultServer != "" {
		config.Server = defaultServer
	}

	// 服务器端口
	fmt.Printf("服务器端口 [默认: %d]: ", defaultPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		config.Port = defaultPort
	} else {
		config.Port, _ = strconv.Atoi(portStr)
	}

	// 密码
	if defaultPassword != "" {
		fmt.Printf("密码 [默认: %s]: ", strings.Repeat("*", len(defaultPassword)))
	} else {
		fmt.Print("密码: ")
	}
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	if password == "" && defaultPassword != "" {
		config.Password = defaultPassword
	} else {
		config.Password = password
	}

	// 加密方式
	fmt.Printf("加密方式 [默认: %s]: ", defaultMethod)
	method, _ := reader.ReadString('\n')
	method = strings.TrimSpace(method)
	if method == "" {
		config.Method = defaultMethod
	} else {
		config.Method = method
	}

	return config
}

// configureVMess 配置 VMess
func configureVMess(reader *bufio.Reader, oldConfig *Config) *VMeSSConfig {
	config := &VMeSSConfig{AlterId: 0, Network: "tcp"}
	
	// 设置默认值
	defaultServer := ""
	defaultPort := 443
	defaultUUID := ""
	defaultNetwork := "tcp"
	defaultPath := "/"
	defaultTLS := false
	
	if oldConfig != nil && oldConfig.ProxyType == "vmess" {
		if oldConfig.ProxyServer != "" {
			defaultServer = oldConfig.ProxyServer
		}
		if oldConfig.ProxyPort > 0 {
			defaultPort = oldConfig.ProxyPort
		}
		if oldConfig.ProxyUUID != "" {
			defaultUUID = oldConfig.ProxyUUID
		}
		if oldConfig.ProxyNetwork != "" {
			defaultNetwork = oldConfig.ProxyNetwork
		}
		if oldConfig.ProxyPath != "" {
			defaultPath = oldConfig.ProxyPath
		}
		defaultTLS = oldConfig.ProxyTLS
	}

	// 服务器地址
	if defaultServer != "" {
		fmt.Printf("\n服务器地址 [默认: %s]: ", defaultServer)
	} else {
		fmt.Print("\n服务器地址: ")
	}
	config.Server, _ = reader.ReadString('\n')
	config.Server = strings.TrimSpace(config.Server)
	if config.Server == "" && defaultServer != "" {
		config.Server = defaultServer
	}

	// 服务器端口
	fmt.Printf("服务器端口 [默认: %d]: ", defaultPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		config.Port = defaultPort
	} else {
		config.Port, _ = strconv.Atoi(portStr)
	}

	// UUID
	if defaultUUID != "" {
		fmt.Printf("UUID [默认: %s]: ", defaultUUID)
	} else {
		fmt.Print("UUID: ")
	}
	uuid, _ := reader.ReadString('\n')
	uuid = strings.TrimSpace(uuid)
	if uuid == "" && defaultUUID != "" {
		config.UUID = defaultUUID
	} else {
		config.UUID = uuid
	}

	// 传输协议
	fmt.Printf("传输协议 [tcp/ws/grpc，默认: %s]: ", defaultNetwork)
	network, _ := reader.ReadString('\n')
	network = strings.TrimSpace(network)
	if network == "" {
		config.Network = defaultNetwork
	} else {
		config.Network = network
	}

	// WebSocket路径
	if config.Network == "ws" {
		fmt.Printf("WebSocket 路径 [默认: %s]: ", defaultPath)
		path, _ := reader.ReadString('\n')
		path = strings.TrimSpace(path)
		if path == "" {
			config.Path = defaultPath
		} else {
			config.Path = path
		}
	}

	// TLS
	config.TLS = askYesNoWithDefault(reader, "是否启用 TLS？", defaultTLS)

	return config
}

// configureDHCP 配置 DHCP
func configureDHCP(reader *bufio.Reader, config *Config, oldConfig *Config) {
	config.EnableDHCP = true

	// 基于网段生成默认范围
	parts := strings.Split(config.HostIP, ".")
	if len(parts) == 4 {
		subnet := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
		config.DHCPStart = fmt.Sprintf("%s.100", subnet)
		config.DHCPEnd = fmt.Sprintf("%s.200", subnet)
	}
	
	// 如果有旧配置，使用旧配置的值
	if oldConfig != nil && oldConfig.EnableDHCP {
		if oldConfig.DHCPStart != "" {
			config.DHCPStart = oldConfig.DHCPStart
		}
		if oldConfig.DHCPEnd != "" {
			config.DHCPEnd = oldConfig.DHCPEnd
		}
	}

	fmt.Printf("\nDHCP 起始地址 [默认: %s]: ", config.DHCPStart)
	start, _ := reader.ReadString('\n')
	start = strings.TrimSpace(start)
	if start != "" && isValidIP(start) {
		config.DHCPStart = start
	}

	fmt.Printf("DHCP 结束地址 [默认: %s]: ", config.DHCPEnd)
	end, _ := reader.ReadString('\n')
	end = strings.TrimSpace(end)
	if end != "" && isValidIP(end) {
		config.DHCPEnd = end
	}
}

// deployXProxy 执行部署
func deployXProxy(config *Config) error {
	// 1. 创建目录（注意：XProxy 内部使用 /xproxy，外部挂载为 /etc/xproxy）
	fmt.Println("\n创建配置目录...")
	dirs := []string{
		"/etc/xproxy",
		"/etc/xproxy/config",
		"/etc/xproxy/assets",
		"/etc/xproxy/custom",
		"/etc/xproxy/log",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %v", err)
		}
	}

	// 2. 开启混杂模式
	fmt.Println("开启网卡混杂模式...")
	cmd := exec.Command("ip", "link", "set", config.Interface, "promisc", "on")
	if err := cmd.Run(); err != nil {
		printWarning("开启混杂模式失败，可能需要手动设置")
	}

	// 3. 创建或复用 macvlan 网络
	fmt.Println("配置 Docker macvlan 网络...")

	// 获取子网信息
	subnet := getSubnet(config.HostIP)
	
	// 查找现有的 macvlan 网络
	var existingMacvlan string
	cmd = exec.Command("docker", "network", "ls", "--filter", "driver=macvlan", "--format", "{{.Name}}")
	output, _ := cmd.Output()
	macvlanNetworks := strings.Split(strings.TrimSpace(string(output)), "\n")
	
	for _, netName := range macvlanNetworks {
		if netName == "" {
			continue
		}
		// 检查网络的子网是否匹配
		inspectCmd := exec.Command("docker", "network", "inspect", netName, "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
		subnetOutput, _ := inspectCmd.Output()
		existingSubnet := strings.TrimSpace(string(subnetOutput))
		
		if existingSubnet == subnet {
			existingMacvlan = netName
			break
		}
	}
	
	// 如果找到了匹配的 macvlan 网络
	if existingMacvlan != "" {
		fmt.Printf("发现已存在的 macvlan 网络 '%s' (子网: %s)\n", existingMacvlan, subnet)
		fmt.Printf("是否使用现有网络？[Y/n]: ")
		
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		
		if answer == "" || answer == "y" || answer == "yes" {
			config.MacvlanName = existingMacvlan
			printSuccess(fmt.Sprintf("将使用现有网络 '%s'", existingMacvlan))
		} else {
			// 用户选择不使用现有网络，创建新的
			fmt.Print("请输入新网络名称 [默认: xproxy-macvlan]: ")
			newName, _ := reader.ReadString('\n')
			newName = strings.TrimSpace(newName)
			if newName == "" {
				newName = "xproxy-macvlan"
			}
			config.MacvlanName = newName
			
			// 创建新网络
			createCmd := exec.Command("docker", "network", "create", "-d", "macvlan",
				"--subnet="+subnet,
				"--gateway="+config.GatewayIP,
				"-o", "parent="+config.Interface,
				"-o", "macvlan_mode=bridge",
				config.MacvlanName)
			
			output, err := createCmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("创建 macvlan 网络失败: %v\n输出: %s", err, string(output))
			}
			printSuccess(fmt.Sprintf("成功创建网络 '%s'", config.MacvlanName))
		}
	} else {
		// 没有找到匹配的网络，创建新的
		config.MacvlanName = "macvlan"  // 默认名称
		fmt.Printf("创建新的 macvlan 网络 '%s'...\n", config.MacvlanName)
		
		createCmd := exec.Command("docker", "network", "create", "-d", "macvlan",
			"--subnet="+subnet,
			"--gateway="+config.GatewayIP,
			"-o", "parent="+config.Interface,
			"-o", "macvlan_mode=bridge",
			config.MacvlanName)
		
		output, err := createCmd.CombinedOutput()
		if err != nil {
			// 如果创建失败，可能是因为已存在同名网络
			if strings.Contains(string(output), "already exists") {
				// 检查是否可以使用这个网络
				inspectCmd := exec.Command("docker", "network", "inspect", config.MacvlanName, "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
				subnetOutput, _ := inspectCmd.Output()
				existingSubnet := strings.TrimSpace(string(subnetOutput))
				
				if existingSubnet == subnet {
					printWarning(fmt.Sprintf("网络 '%s' 已存在且子网匹配，将使用该网络", config.MacvlanName))
				} else {
					return fmt.Errorf("网络 '%s' 已存在但子网不匹配 (期望: %s, 实际: %s)", config.MacvlanName, subnet, existingSubnet)
				}
			} else {
				return fmt.Errorf("创建 macvlan 网络失败: %v\n输出: %s", err, string(output))
			}
		} else {
			printSuccess(fmt.Sprintf("成功创建网络 '%s'", config.MacvlanName))
		}
	}

	// 4. 生成配置文件
	fmt.Println("生成配置文件...")
	if err := generateConfigs(config); err != nil {
		return fmt.Errorf("生成配置文件失败: %v", err)
	}

	// 5. 停止旧容器（如果存在）
	exec.Command("docker", "stop", "xproxy").Run()
	exec.Command("docker", "rm", "xproxy").Run()

	// 6. 启动容器
	fmt.Println("启动 XProxy 容器...")
	
	// 启动前再次检查 IP 是否可用
	fmt.Printf("检查 IP 地址 %s 可用性...\n", config.ProxyIP)
	if isIPInUse(config.ProxyIP) {
		// 尝试找出占用者
		cmd = exec.Command("docker", "ps", "-a", "--format", "{{.Names}}")
		output, _ := cmd.Output()
		containers := strings.Split(strings.TrimSpace(string(output)), "\n")
		
		for _, container := range containers {
			if container == "" || container == "xproxy" {
				continue
			}
			// 获取容器在 macvlan 网络中的 IP
			inspectCmd := exec.Command("docker", "inspect", "-f", 
				fmt.Sprintf("{{.NetworkSettings.Networks.%s.IPAddress}}", config.MacvlanName), 
				container)
			ipOutput, _ := inspectCmd.Output()
			containerIP := strings.TrimSpace(string(ipOutput))
			
			if containerIP == config.ProxyIP {
				return fmt.Errorf("IP 地址 %s 已被容器 '%s' 占用\n请选择其他 IP 地址或停止该容器", config.ProxyIP, container)
			}
		}
		
		return fmt.Errorf("IP 地址 %s 已被占用\n请运行 'arp -n | grep %s' 查看占用者", config.ProxyIP, config.ProxyIP)
	}
	
	cmd = exec.Command("docker", "run", "-d",
		"--name", "xproxy",
		"--privileged",
		"--network", config.MacvlanName,
		"--ip", config.ProxyIP,
		"--restart", "unless-stopped",
		"-v", "/etc/xproxy:/xproxy", // 注意：容器内部路径是 /xproxy
		"-v", "/etc/timezone:/etc/timezone:ro",
		"-v", "/etc/localtime:/etc/localtime:ro",
		"dnomd343/xproxy:latest")

	if output, err := cmd.CombinedOutput(); err != nil {
		// 如果是地址已被使用的错误，提供更详细的信息
		if strings.Contains(string(output), "Address already in use") {
			return fmt.Errorf("启动容器失败: IP 地址 %s 已被占用\n输出: %s\n\n请尝试:\n1. 选择其他 IP 地址\n2. 检查占用该 IP 的服务: docker network inspect %s", 
				config.ProxyIP, string(output), config.MacvlanName)
		}
		return fmt.Errorf("启动容器失败: %v\n%s", err, string(output))
	}

	// 7. 如果启用了 IPv6，在主机上配置 IPv6 透明代理
	if config.EnableIPv6 {
		fmt.Println("配置 IPv6 透明代理...")
		if err := setupIPv6TransparentProxy(); err != nil {
			printWarning("IPv6 透明代理配置失败: " + err.Error())
		} else {
			printSuccess("✓ IPv6 透明代理配置完成")
		}
	}

	return nil
}

// generateConfigs 生成配置文件
func generateConfigs(config *Config) error {
	// 生成 xproxy.yml
	xproxyConfig := generateXProxyYML(config)
	if err := os.WriteFile("/etc/xproxy/xproxy.yml", []byte(xproxyConfig), 0644); err != nil {
		return err
	}

	// 生成 outbounds.json
	var outboundsJSON string
	if config.ProxyType == "freedom" {
		// 直连模式
		outboundsJSON = generateFreedomOutbound()
	} else if config.ProxyConfig != nil {
		outboundsJSON = config.ProxyConfig.GenerateJSON()
	} else {
		// 自定义模式，生成模板
		outboundsJSON = generateTemplateOutbound()
	}

	if err := os.WriteFile("/etc/xproxy/config/outbounds.json", []byte(outboundsJSON), 0644); err != nil {
		return err
	}

	// 生成 routing.json
	routingJSON := generateRoutingJSON()
	if err := os.WriteFile("/etc/xproxy/config/routing.json", []byte(routingJSON), 0644); err != nil {
		return err
	}

	// 生成 dns.json
	dnsJSON := generateDNSJSON(config)
	if err := os.WriteFile("/etc/xproxy/config/dns.json", []byte(dnsJSON), 0644); err != nil {
		return err
	}

	// 生成 inbounds.json (包含 DNS 入站)
	inboundsJSON := generateInboundsJSON()
	if err := os.WriteFile("/etc/xproxy/config/inbounds.json", []byte(inboundsJSON), 0644); err != nil {
		return err
	}

	// 生成 IPv6 设置脚本（如果启用）
	if config.EnableIPv6 {
		if err := generateIPv6Script(); err != nil {
			return fmt.Errorf("生成 IPv6 脚本失败: %v", err)
		}
	}

	return nil
}

// setupIPv6TransparentProxy 在主机上设置 IPv6 透明代理
func setupIPv6TransparentProxy() error {
	// 等待容器完全启动
	time.Sleep(3 * time.Second)

	// 检查是否已经配置过
	checkCmd := exec.Command("ip", "-6", "rule", "show")
	output, _ := checkCmd.Output()
	if strings.Contains(string(output), "fwmark 1 lookup 101") {
		fmt.Println("IPv6 规则已存在，跳过配置")
		return nil
	}

	fmt.Println("设置 IPv6 路由规则...")
	
	// 设置 IPv6 路由规则
	// 首先确保路由表存在
	exec.Command("ip", "-6", "route", "flush", "table", "101").Run()
	
	cmds := [][]string{
		{"ip", "-6", "rule", "add", "fwmark", "1", "table", "101"},
		{"ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "101"},
	}
	
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// 如果是 "RTNETLINK answers: File exists" 错误，忽略它
			if strings.Contains(string(output), "File exists") {
				continue
			}
			return fmt.Errorf("执行命令失败 %v: %v, 输出: %s", args, err, string(output))
		}
	}

	// 清理旧的 IPv6 防火墙规则
	exec.Command("ip6tables", "-t", "mangle", "-F", "XPROXY6").Run()
	exec.Command("ip6tables", "-t", "mangle", "-X", "XPROXY6").Run()

	// 创建 IPv6 TPROXY 链
	if err := exec.Command("ip6tables", "-t", "mangle", "-N", "XPROXY6").Run(); err != nil {
		// 链可能已存在，继续
	}

	// 添加绕过规则
	rules := [][]string{
		{"-A", "XPROXY6", "-d", "::1/128", "-j", "RETURN"},
		{"-A", "XPROXY6", "-d", "fe80::/10", "-j", "RETURN"},
		{"-A", "XPROXY6", "-d", "fc00::/7", "-j", "RETURN"},
		{"-A", "XPROXY6", "-d", "ff00::/8", "-j", "RETURN"},
	}

	// 获取本地 IPv6 地址并添加到绕过列表
	ifaceCmd := exec.Command("ip", "-6", "addr", "show")
	if output, err := ifaceCmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet6") && !strings.Contains(line, "fe80") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					addr := fields[1]
					if addr != "" {
						rules = append(rules, []string{"-A", "XPROXY6", "-d", addr, "-j", "RETURN"})
					}
				}
			}
		}
	}

	// 设置 TPROXY 规则
	rules = append(rules, 
		[]string{"-A", "XPROXY6", "-p", "tcp", "-j", "TPROXY", "--on-port", "7289", "--tproxy-mark", "0x1/0x1"},
		[]string{"-A", "XPROXY6", "-p", "udp", "-j", "TPROXY", "--on-port", "7289", "--tproxy-mark", "0x1/0x1"},
	)

	// 应用所有规则
	for _, rule := range rules {
		args := append([]string{"-t", "mangle"}, rule...)
		cmd := exec.Command("ip6tables", args...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("添加 ip6tables 规则失败 %v: %v", rule, err)
		}
	}

	// 删除旧的 PREROUTING 规则（如果存在）
	exec.Command("ip6tables", "-t", "mangle", "-D", "PREROUTING", "-j", "XPROXY6").Run()
	
	// 应用到 PREROUTING 链
	if err := exec.Command("ip6tables", "-t", "mangle", "-A", "PREROUTING", "-j", "XPROXY6").Run(); err != nil {
		return fmt.Errorf("添加 PREROUTING 规则失败: %v", err)
	}

	// 配置 IPv6 转发
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()
	exec.Command("sysctl", "-w", "net.ipv6.conf.default.forwarding=1").Run()

	return nil
}

// generateIPv6Script 生成 IPv6 配置脚本
func generateIPv6Script() error {
	script := `#!/bin/sh
# XProxy IPv6 透明代理配置脚本

# 等待 XProxy 启动
sleep 3

# 检查是否已经配置过
if ip -6 rule show | grep -q "fwmark 1 lookup 101"; then
    echo "IPv6 rules already configured"
    exit 0
fi

echo "Configuring IPv6 transparent proxy..."

# 设置 IPv6 路由规则
ip -6 rule add fwmark 1 table 101
ip -6 route add local ::/0 dev lo table 101

# 清理旧的 IPv6 防火墙规则
ip6tables -t mangle -F XPROXY6 2>/dev/null
ip6tables -t mangle -X XPROXY6 2>/dev/null

# 创建 IPv6 TPROXY 链
ip6tables -t mangle -N XPROXY6

# 添加绕过规则
ip6tables -t mangle -A XPROXY6 -d ::1/128 -j RETURN
ip6tables -t mangle -A XPROXY6 -d fe80::/10 -j RETURN
ip6tables -t mangle -A XPROXY6 -d fc00::/7 -j RETURN
ip6tables -t mangle -A XPROXY6 -d ff00::/8 -j RETURN

# 获取本地 IPv6 地址并添加到绕过列表
for addr in $(ip -6 addr show dev eth0 | grep 'inet6' | grep -v 'fe80' | awk '{print $2}'); do
    ip6tables -t mangle -A XPROXY6 -d $addr -j RETURN
done

# 设置 TPROXY 规则
ip6tables -t mangle -A XPROXY6 -p tcp -j TPROXY --on-port 7289 --tproxy-mark 0x1/0x1
ip6tables -t mangle -A XPROXY6 -p udp -j TPROXY --on-port 7289 --tproxy-mark 0x1/0x1

# 应用到 PREROUTING 链
ip6tables -t mangle -D PREROUTING -j XPROXY6 2>/dev/null
ip6tables -t mangle -A PREROUTING -j XPROXY6

# 配置 IPv6 转发
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/default/forwarding

echo "IPv6 transparent proxy configuration completed"
`

	scriptPath := "/etc/xproxy/custom/setup-ipv6.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return err
	}

	return nil
}

// generateXProxyYML 生成主配置文件
func generateXProxyYML(config *Config) string {
	// 获取子网掩码位数
	subnet := getSubnet(config.HostIP)
	maskBits := "24"
	if strings.Contains(subnet, "/") {
		parts := strings.Split(subnet, "/")
		if len(parts) == 2 {
			maskBits = parts[1]
		}
	}
	
	yml := fmt.Sprintf(`proxy:
  log: info
  core: xray

network:
  dev: %s
  ipv4:
    gateway: %s
    address: %s/%s
  bypass:
    - 127.0.0.0/8      # IPv4 loopback
    - 169.254.0.0/16   # IPv4 link-local
    - 224.0.0.0/4      # IPv4 multicast
    - 240.0.0.0/4      # IPv4 reserved
    - ::1/128          # IPv6 loopback
    - fc00::/7         # IPv6 unique local
    - fe80::/10        # IPv6 link-local
    - ff00::/8         # IPv6 multicast`, "eth0", config.GatewayIP, config.ProxyIP, maskBits)
	
	// 如果启用 IPv6，添加 IPv6 网络配置
	if config.EnableIPv6 && config.IPv6Prefix != "" {
		ipv6Address := generateIPv6Address(config.IPv6Prefix)
		if ipv6Address != "" {
			yml += fmt.Sprintf(`
  ipv6:
    gateway: %s
    address: %s`, config.IPv6Gateway, ipv6Address)
		}
	}
	
	yml += `

asset:
  update:
    cron: "0 5 6 * * *"
    url:
      geoip.dat: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
      geosite.dat: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
`

	// IPv6 配置现在由主机直接处理，不需要 custom 脚本
	// 注意：透明代理模式下不启用 RADVD，避免影响客户端路由

	if config.EnableDHCP {
		dhcpConfig := fmt.Sprintf(`
dhcp:
  ipv4:
    enable: true
    config: |
      start %s
      end %s
      interface eth0
      option dns %s
      option subnet 255.255.255.0
      option router %s
`, config.DHCPStart, config.DHCPEnd, config.ProxyIP, config.ProxyIP)
		yml += dhcpConfig
	}

	return yml
}

// generateInboundsJSON 生成入站配置（包含 DNS 和 IPv6）
func generateInboundsJSON() string {
	return `{
  "inbounds": [
    {
      "tag": "tproxy4",
      "port": 7288,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "tag": "tproxy6",
      "port": 7289,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "tag": "dns-in",
      "port": 53,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "8.8.8.8",
        "port": 53,
        "network": "tcp,udp"
      }
    }
  ]
}`
}

// generateFreedomOutbound 生成直连出站
func generateFreedomOutbound() string {
	return `{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}`
}

// generateTemplateOutbound 生成模板出站
func generateTemplateOutbound() string {
	return `{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "your-server.com",
            "port": 443,
            "users": [
              {
                "id": "your-uuid",
                "alterId": 0,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {
          "path": "/"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}`
}

// GenerateJSON 实现 ShadowsocksConfig
func (c *ShadowsocksConfig) GenerateJSON() string {
	template := `{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "%s",
            "port": %d,
            "password": "%s",
            "method": "%s"
          }
        ]
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}`
	return fmt.Sprintf(template, c.Server, c.Port, c.Password, c.Method)
}

// GenerateJSON 实现 VMeSSConfig
func (c *VMeSSConfig) GenerateJSON() string {
	streamSettings := ""
	if c.Network == "ws" {
		security := ""
		if c.TLS {
			security = `"security": "tls",`
		}
		streamSettings = fmt.Sprintf(`,
      "streamSettings": {
        "network": "ws",
        %s
        "wsSettings": {
          "path": "%s"
        }
      }`, security, c.Path)
	}

	template := `{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "%s",
            "port": %d,
            "users": [
              {
                "id": "%s",
                "alterId": %d,
                "security": "auto"
              }
            ]
          }
        ]
      }%s
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}`
	return fmt.Sprintf(template, c.Server, c.Port, c.UUID, c.AlterId, streamSettings)
}

// generateRoutingJSON 生成路由配置
func generateRoutingJSON() string {
	return `{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["dns-in"],
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:cn",
          "geosite:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:cn",
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "network": "tcp,udp"
      }
    ]
  }
}`
}

// generateDNSJSON 生成 DNS 配置
func generateDNSJSON(config *Config) string {
	dns := `{
  "dns": {
    "servers": [`
	
	// 如果禁用IPv6 DNS，为每个服务器单独设置queryStrategy
	if config.DisableIPv6DNS {
		dns += `
      {
        "address": "223.5.5.5",
        "port": 53,
        "domains": [
          "geosite:cn"
        ],
        "queryStrategy": "UseIPv4"
      },
      {
        "address": "8.8.8.8",
        "port": 53,
        "domains": [
          "geosite:geolocation-!cn"
        ],
        "queryStrategy": "UseIPv4"
      },
      {
        "address": "1.1.1.1",
        "queryStrategy": "UseIPv4"
      },
      {
        "address": "localhost",
        "queryStrategy": "UseIPv4"
      }`
	} else {
		dns += `
      {
        "address": "223.5.5.5",
        "port": 53,
        "domains": [
          "geosite:cn"
        ]
      },
      {
        "address": "8.8.8.8",
        "port": 53,
        "domains": [
          "geosite:geolocation-!cn"
        ]
      },
      "1.1.1.1",
      "localhost"`
	}
	
	dns += `
    ]`
	
	// 全局queryStrategy设置
	if config.DisableIPv6DNS {
		dns += `,
    "queryStrategy": "UseIPv4"`
	}
	
	dns += `
  }
}`
	
	return dns
}

// verifyDeployment 验证部署
func verifyDeployment(config *Config) error {
	fmt.Println("\n等待容器启动...")
	time.Sleep(3 * time.Second)

	// 1. 检查容器状态
	fmt.Print("检查容器状态... ")
	cmd := exec.Command("docker", "ps", "--filter", "name=xproxy", "--format", "{{.Status}}")
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "Up") {
		return fmt.Errorf("容器未正常运行")
	}
	printSuccess("✓")

	// 2. 检查端口监听
	fmt.Print("检查端口监听... ")
	cmd = exec.Command("docker", "exec", "xproxy", "netstat", "-tlnpu")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("无法检查端口状态")
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, ":53") {
		printWarning("DNS 端口未监听")
	}
	if !strings.Contains(outputStr, ":7288") {
		return fmt.Errorf("透明代理端口未监听")
	}
	printSuccess("✓")

	// 3. 检查进程
	fmt.Print("检查 Xray 进程... ")
	cmd = exec.Command("docker", "exec", "xproxy", "ps", "aux")
	output, err = cmd.Output()
	if err != nil || !strings.Contains(string(output), "xray") {
		return fmt.Errorf("Xray 进程未运行")
	}
	printSuccess("✓")

	// 4. 检查容器网络
	fmt.Print("检查容器网络... ")
	cmd = exec.Command("docker", "exec", "xproxy", "ip", "addr", "show", "eth0")
	output, err = cmd.Output()
	if err != nil || !strings.Contains(string(output), config.ProxyIP) {
		return fmt.Errorf("容器网络配置异常")
	}
	printSuccess("✓")

	return nil
}

// 辅助函数
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isIPInUse 检查 IP 地址是否已被占用
func isIPInUse(ip string) bool {
	// 1. 获取所有 macvlan 类型的网络
	cmd := exec.Command("docker", "network", "ls", "--filter", "driver=macvlan", "--format", "{{.Name}}")
	output, err := cmd.Output()
	if err == nil {
		macvlanNetworks := strings.Fields(string(output))
		
		// 检查每个 macvlan 网络中的容器 IP
		for _, network := range macvlanNetworks {
			// 使用 docker network inspect 获取该网络中所有容器的 IP
			inspectCmd := exec.Command("docker", "network", "inspect", network, 
				"--format", "{{range .Containers}}{{.IPv4Address}} {{end}}")
			ipOutput, err := inspectCmd.Output()
			if err == nil {
				ips := strings.Fields(string(ipOutput))
				for _, ipWithMask := range ips {
					containerIP := strings.Split(ipWithMask, "/")[0]
					if containerIP == ip {
						return true
					}
				}
			}
		}
	}
	
	// 2. 检查 ARP 表（对于物理网络中的设备）
	cmd = exec.Command("arp", "-n")
	output, _ = cmd.Output()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Address") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == ip {
			if fields[1] == "(incomplete)" {
				// incomplete 不代表被占用
				continue
			}
			// 有有效 MAC 地址，说明 IP 被占用
			return true
		}
	}
	
	// 3. 最后尝试 ping（对于非 macvlan 的情况）
	cmd = exec.Command("ping", "-c", "1", "-W", "0.2", ip)
	err = cmd.Run()
	if err == nil {
		return true
	}
	
	return false
}

// getUsedIPsInSubnet 批量获取子网中已使用的 IP
func getUsedIPsInSubnet(subnet string) map[string]bool {
	usedIPs := make(map[string]bool)
	
	// 从 ARP 表获取
	cmd := exec.Command("arp", "-n")
	output, _ := cmd.Output()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 1 && strings.HasPrefix(fields[0], subnet) {
			usedIPs[fields[0]] = true
		}
	}
	
	// 获取所有 macvlan 网络中的容器 IP
	networks := []string{"macvlan", "openwrt", "xproxy-macvlan"}
	for _, network := range networks {
		cmd = exec.Command("docker", "network", "inspect", network, 
			"--format", "{{range .Containers}}{{.IPv4Address}} {{end}}")
		output, _ = cmd.Output()
		ips := strings.Fields(string(output))
		for _, ipWithMask := range ips {
			ip := strings.Split(ipWithMask, "/")[0]
			if ip != "" && strings.HasPrefix(ip, subnet) {
				usedIPs[ip] = true
			}
		}
	}
	
	return usedIPs
}

// findAvailableIP 查找可用的 IP 地址
func findAvailableIP(octet1, octet2, octet3, preferredIP string) string {
	subnet := fmt.Sprintf("%s.%s.%s.", octet1, octet2, octet3)
	
	// 如果有首选 IP，先检查它
	if preferredIP != "" && isValidIP(preferredIP) {
		if !isIPInUse(preferredIP) {
			return preferredIP
		}
	}
	
	// 从 .2 开始查找可用的 IP（只找一个就返回）
	for i := 2; i <= 254; i++ {
		testIP := fmt.Sprintf("%s%d", subnet, i)
		// 快速检查是否可用
		if !isIPInUse(testIP) {
			return testIP
		}
	}
	
	// 如果都被占用，返回 .2
	return fmt.Sprintf("%s%d", subnet, 2)
}

// findNextAvailableIP 从指定 IP 开始查找下一个可用的 IP
func findNextAvailableIP(octet1, octet2, octet3, currentIP string) string {
	parts := strings.Split(currentIP, ".")
	if len(parts) != 4 {
		return currentIP
	}
	
	lastOctet, err := strconv.Atoi(parts[3])
	if err != nil {
		return currentIP
	}
	
	// 从下一个 IP 开始查找
	for i := lastOctet + 1; i <= 254; i++ {
		testIP := fmt.Sprintf("%s.%s.%s.%d", octet1, octet2, octet3, i)
		if !isIPInUse(testIP) {
			return testIP
		}
	}
	
	// 如果后面都被占用，从头开始找
	for i := 2; i < lastOctet; i++ {
		testIP := fmt.Sprintf("%s.%s.%s.%d", octet1, octet2, octet3, i)
		if !isIPInUse(testIP) {
			return testIP
		}
	}
	
	return currentIP
}

// showIPUsageInfo 显示 IP 占用信息
func showIPUsageInfo(ip string) {
	// 1. 获取所有 macvlan 网络并检查
	cmd := exec.Command("docker", "network", "ls", "--filter", "driver=macvlan", "--format", "{{.Name}}")
	output, err := cmd.Output()
	if err == nil {
		macvlanNetworks := strings.Fields(string(output))
		
		for _, network := range macvlanNetworks {
			// 获取该网络的详细信息，包括容器
			inspectCmd := exec.Command("docker", "network", "inspect", network, 
				"--format", "{{range $k, $v := .Containers}}{{$k}}:{{$v.IPv4Address}} {{end}}")
			containerOutput, err := inspectCmd.Output()
			if err == nil {
				// 解析容器ID和IP
				pairs := strings.Fields(string(containerOutput))
				for _, pair := range pairs {
					parts := strings.Split(pair, ":")
					if len(parts) == 2 {
						containerID := parts[0]
						ipWithMask := parts[1]
						containerIP := strings.Split(ipWithMask, "/")[0]
						
						if containerIP == ip {
							// 获取容器名称
							nameCmd := exec.Command("docker", "inspect", "-f", "{{.Name}}", containerID)
							nameOutput, _ := nameCmd.Output()
							containerName := strings.TrimSpace(strings.TrimPrefix(string(nameOutput), "/"))
							fmt.Printf("占用者: Docker 容器 '%s' (网络: %s)\n", containerName, network)
							return
						}
					}
				}
			}
		}
	}
	
	// 检查 ARP 表获取 MAC 地址
	cmd = exec.Command("arp", "-n")
	output, _ = cmd.Output()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// 跳过标题行
		if strings.Contains(line, "Address") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		// ARP 表格式：IP地址 HWtype MAC地址 Flags Mask 接口
		if len(fields) >= 2 && fields[0] == ip {
			// 如果是 incomplete，不应该显示占用信息
			if fields[1] == "(incomplete)" {
				return
			}
			// 检查是否是有效的 MAC 地址
			if len(fields) >= 3 && len(fields[2]) == 17 && strings.Contains(fields[2], ":") {
				fmt.Printf("占用者 MAC 地址: %s\n", fields[2])
			} else if len(fields) >= 3 {
				fmt.Printf("占用者 MAC 地址: %s\n", fields[2])
			}
			return
		}
	}
	
	fmt.Println("占用者: 未知设备")
}

func getSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return "192.168.1.0/24"
}

func askYesNo(reader *bufio.Reader, question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// askYesNoWithDefault 带默认值的是否询问
func askYesNoWithDefault(reader *bufio.Reader, question string, defaultValue bool) bool {
	defaultStr := "N"
	if defaultValue {
		defaultStr = "Y"
	}
	fmt.Printf("%s [y/N] [默认: %s]: ", question, defaultStr)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	
	// 如果用户直接回车，使用默认值
	if answer == "" {
		return defaultValue
	}
	
	return answer == "y" || answer == "yes"
}

func displayConfig(config *Config) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("主机 IP: %s\n", config.HostIP)
	fmt.Printf("网关 IP: %s\n", config.GatewayIP)
	fmt.Printf("网络接口: %s\n", config.Interface)
	fmt.Printf("旁路由 IP: %s\n", config.ProxyIP)
	if config.MacvlanName != "" {
		fmt.Printf("Docker 网络: %s\n", config.MacvlanName)
	}
	fmt.Printf("代理类型: %s\n", config.ProxyType)
	if config.EnableDHCP {
		fmt.Printf("DHCP: 启用 (%s - %s)\n", config.DHCPStart, config.DHCPEnd)
	} else {
		fmt.Println("DHCP: 禁用")
	}
	if config.EnableIPv6 {
		fmt.Println("IPv6: 启用")
		if config.IPv6Prefix != "" {
			fmt.Printf("  - 前缀: %s\n", config.IPv6Prefix)
		}
		if config.IPv6Gateway != "" {
			fmt.Printf("  - 网关: %s\n", config.IPv6Gateway)
		}
	} else {
		fmt.Println("IPv6: 禁用")
	}
	if config.DisableIPv6DNS {
		fmt.Println("DNS 策略: 仅 IPv4 解析")
	} else {
		fmt.Println("DNS 策略: IPv4 + IPv6 解析")
	}
	fmt.Println(strings.Repeat("=", 50))
}

func printError(msg string) {
	fmt.Println(ColorRed + "✗ " + msg + ColorReset)
}

func printSuccess(msg string) {
	fmt.Println(ColorGreen + msg + ColorReset)
}

func printWarning(msg string) {
	fmt.Println(ColorYellow + "⚠ " + msg + ColorReset)
}

func printInfo(msg string) {
	fmt.Println(ColorCyan + "ℹ " + msg + ColorReset)
}

// saveConfig 保存配置到文件
func saveConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile, data, 0644)
}

// loadConfig 从文件加载配置
func loadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return &config, nil
}
