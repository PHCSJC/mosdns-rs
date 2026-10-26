#!/bin/bash
# 一键回滚到 Go 版 mosdns
#
# 注意：/etc/mosdns/config.yaml 里有 mosdns-rs 专属的 log.max_size_mb / log.keep，
#       原版 mosdns 用 ErrorUnused=true 解析配置，遇到这两个 key 会启动失败。
#       所以这里生成一份去掉这两个 key 的 /etc/mosdns/config-go.yaml 给 Go 版用，
#       原配置保持不动（随时可以再切回 mosdns-rs）。
set -e

echo "[1/4] 停掉并禁用 mosdns-rs.service"
systemctl stop mosdns-rs 2>/dev/null || true
systemctl disable mosdns-rs 2>/dev/null || true
pkill -x mosdns-rs 2>/dev/null || true
sleep 1

echo "[2/4] 生成 Go 版可用配置（摘掉 log.max_size_mb / log.keep）"
sed -e '/^  max_size_mb:/d' -e '/^  keep:/d' /etc/mosdns/config.yaml > /etc/mosdns/config-go.yaml
sed -n '1,6p' /etc/mosdns/config-go.yaml

echo "[3/4] 启动 Go 版"
setsid nohup /usr/local/bin/mosdns start -c /etc/mosdns/config-go.yaml >/var/log/mosdns.out 2>&1 </dev/null &
sleep 3

echo "[4/4] 检查"
ps -o pid,etime,rss,cmd -C mosdns || true
ss -lntup | grep ':53 ' || true
dig @127.0.0.1 www.baidu.com A +short +time=3 | head -2

echo
echo "回滚完成。想再切回 mosdns-rs：systemctl enable --now mosdns-rs"
echo "（Go 版用的是 /etc/mosdns/config-go.yaml，原 /etc/mosdns/config.yaml 未被改动）"
