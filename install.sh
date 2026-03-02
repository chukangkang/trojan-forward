#!/bin/bash

# Trojan 自动安装脚本
# 使用 systemd service 启动

set -e

REPO_URL="https://raw.githubusercontent.com/chukangkang/trojan-forward/master"
INSTALL_DIR="/opt/trojan"
SERVICE_DIR="/etc/systemd/system"
CONFIG_FILE="server-socks5.json"

echo "=== Trojan 安装脚本 ==="

# 创建安装目录
echo "[1/6] 创建安装目录..."
mkdir -p "$INSTALL_DIR"

# 下载 trojan 二进制文件
echo "[2/6] 下载 trojan 二进制文件..."
curl -fSL "$REPO_URL/build/trojan" -o "$INSTALL_DIR/trojan"
chmod +x "$INSTALL_DIR/trojan"

# 下载配置文件
echo "[3/6] 下载配置文件..."
curl -fSL "$REPO_URL/example/server-socks5.json-example" -o "$INSTALL_DIR/$CONFIG_FILE"

# 编辑配置文件
echo "[4/6] 请编辑配置文件 ($INSTALL_DIR/$CONFIG_FILE)"
echo "    修改 password、ssl 证书路径、socks5 配置等"
read -p "按回车继续..."

# 下载 service 文件
echo "[5/6] 安装 systemd service..."
curl -fSL "$REPO_URL/example/trojan.service" -o "$SERVICE_DIR/trojan.service"

# 重新加载 systemd
systemctl daemon-reload

# 启用并启动服务
echo "[6/6] 启动 trojan 服务..."
systemctl enable trojan
systemctl start trojan

# 检查状态
systemctl status trojan --no-pager

echo ""
echo "=== 安装完成 ==="
echo "管理命令:"
echo "  启动: systemctl start trojan"
echo "  停止: systemctl stop trojan"
echo "  重启: systemctl restart trojan"
echo "  状态: systemctl status trojan"
