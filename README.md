# Hysteria 2 一键安装脚本 (Alpine/Debian/Ubuntu/CentOS)

此脚本支持在 Alpine Linux 以及常见的 Debian/Ubuntu/CentOS 系统上自动安装 Hysteria 2。

## 特性
- 自动识别系统架构 (amd64, arm64, etc.)
- 自动获取并下载 GitHub 最新版本 Hysteria 2
- 支持 Alpine Linux (OpenRC) 和 Systemd 系统
- 更加安全的证书权限管理

## 一键安装

使用 root 用户在终端执行以下命令：

```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/fiat24/hy2/master/hy2.sh && chmod +x hy2.sh && bash hy2.sh
```

或者使用 curl：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/fiat24/hy2/master/hy2.sh)
```
