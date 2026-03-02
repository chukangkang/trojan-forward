#!/bin/bash

# Trojan 自动卸载脚本

set -e

INSTALL_DIR="/opt/trojan"
SERVICE_NAME="trojan"

echo "=== Trojan 卸载脚本 ==="

# 停止并禁用服务
echo "[1/4] 停止服务..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# 删除 service 文件
echo "[2/4] 删除 service 文件..."
rm -f /etc/systemd/system/"$SERVICE_NAME.service"
systemctl daemon-reload

# 删除安装目录
echo "[3/4] 删除安装目录..."
rm -rf "$INSTALL_DIR"

echo "[4/4] 完成"

echo ""
echo "=== 卸载完成 ==="
