# dnsmasq: Out-of-Bailiwick Authority NS Records Forwarded Without Sanitization (Cache Poisoning)

## Summary

dnsmasq (tested v2.91) does not perform **bailiwick checking** on NS records in the Authority section of upstream DNS responses. When acting as a forwarding resolver, dnsmasq caches and serves out-of-bailiwick NS RRsets received from an upstream authoritative server, enabling **DNS cache poisoning** via a legitimate response path — no IP spoofing, TXID guessing, or race conditions required.

This vulnerability class has been confirmed and assigned CVEs in other DNS implementations:

- **CVE-2021-25220** — BIND9
- **CVE-2025-11411** — Unbound
- **CVE-2022-32983** — Knot Resolver

## Affected Version

- **dnsmasq v2.91** (latest stable as of testing date)
- Likely affects all prior versions with forwarding/caching enabled

## Vulnerability Details

### Attack Mechanism

1. The attacker owns and operates a **legitimate** authoritative DNS server for a zone they control (e.g., `attacker.lab`).
2. When this server receives a query for `*.attacker.lab`, it returns a valid response containing:
   - **Answer section**: A legitimate A record for the queried name (in-bailiwick).
   - **Authority section**: Malicious NS records for a **different** zone the attacker does NOT control (e.g., `victim.lab NS ns1.evil.attacker.lab.`).
   - **Additional section**: Glue A records pointing the malicious NS names to the attacker's IP.
3. The target dnsmasq instance forwards a client query for `test.attacker.lab` to the attacker's authoritative server.
4. The response passes **all** standard DNS validation checks:
   - Transaction ID matches ✓
   - Source IP matches configured upstream ✓
   - Question section matches ✓
   - Answer is in-bailiwick for `attacker.lab` ✓
5. **dnsmasq fails to reject** the out-of-bailiwick Authority NS records (`victim.lab` is NOT a subdomain of `attacker.lab`) and forwards them to the client.
6. If a downstream caching resolver or stub resolver trusts dnsmasq's response (common in LAN deployments), the poisoned NS delegation for `victim.lab` enters the cache.

### Why This Matters

Per **RFC 2181 §5.4.1** and **RFC 5452 §6**, resolvers and forwarders MUST discard data outside the authoritative scope (bailiwick) of the responding server. Specifically:

> *"**RFC 2181 §5.4.1** treats DNS data with different trust rankings depending on its source, and says low-trust data from additional sections or non-authoritative authority sections should not be cached in a way that allows it to later answer queries. **RFC 5452 §6** further advises resolvers to accept data only when the sender is authoritative for the QNAME or a parent of the QNAME, i.e. to limit acceptance to in-domain data."*

dnsmasq violates this requirement by blindly forwarding Authority section NS records without verifying their relationship to the queried zone.

## Steps to Reproduce

Full reproduction scripts and PoC files are available at:

https://github.com/APEvul-cyber/dns_dnsmasq_vul/tree/main/Spoofed_Response_Authority_NS_RDATA_response

### Environment Setup

| Component                    | Role                                                         | Port |
| ---------------------------- | ------------------------------------------------------------ | ---- |
| **BIND9**                    | Legitimate authoritative server for `victim.lab` (returns `www.victim.lab A → 1.2.3.4`) | 9053 |
| **dnsmasq v2.91**            | Target resolver under test (forwards `attacker.lab` → malicious auth server) | 5322 |
| **malicious_auth_server.py** | Attacker-controlled authoritative server for `attacker.lab`  | 9953 |

### Reproduction Steps

```bash
# 1. Start the malicious authoritative server
python3 malicious_auth_server.py --port 9953 &

# 2. Restart dnsmasq to clear cache
docker restart dnsmasq && sleep 2

# 3. Baseline: verify normal resolution
dig @127.0.0.1 -p 5322 www.victim.lab A +short
# Expected: 1.2.3.4

# 4. Trigger: query through dnsmasq → malicious auth server
dig @127.0.0.1 -p 5322 test.attacker.lab A

# 5. Check: query victim.lab NS — are evil NS records present?
dig @127.0.0.1 -p 5322 victim.lab NS

# 6. Verify: query www.victim.lab A — is traffic hijacked?
dig @127.0.0.1 -p 5322 www.victim.lab A
```

Or run the automated test:

```bash
python3 test_cache_poison.py \
    --target-ip 127.0.0.1 --target-port 5322 --target-name "dnsmasq" --wait 3
```

### Observed Behavior (dnsmasq — VULNERABLE)

After triggering the attack via `dig @127.0.0.1 -p 5322 test.attacker.lab A`, subsequent queries reveal dnsmasq forwarded the out-of-bailiwick records:

```
;; AUTHORITY SECTION:
victim.lab.       86400  IN  NS  ns1.evil.attacker.lab.
victim.lab.       86400  IN  NS  ns2.evil.attacker.lab.

;; ADDITIONAL SECTION:
ns1.evil.attacker.lab.  86400  IN  A  172.21.0.99
ns2.evil.attacker.lab.  86400  IN  A  172.21.0.99
```

### Expected Behavior (Technitium DNS Server — NOT VULNERABLE)

As a comparison, Technitium DNS Server (v14.3) tested under identical conditions correctly **strips** the out-of-bailiwick Authority NS records from the response before forwarding to clients. The victim.lab NS query returns only the legitimate NS records from BIND9.

## Security Impact

| Impact                   | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| **Cache Poisoning**      | Downstream caching resolvers that trust dnsmasq's forwarded responses will cache the attacker's NS delegation for `victim.lab` |
| **Traffic Hijacking**    | All DNS queries for `*.victim.lab` from clients behind dnsmasq are redirected to the attacker's server (`172.21.0.99`) for the TTL duration (86400s) |
| **Phishing / MitM**      | The attacker can serve arbitrary A/MX/TXT records for the victim zone, enabling website spoofing, email interception, and TLS certificate mis-issuance |
| **Persistence**          | A single malicious response poisons the cache for 24 hours (TTL=86400); no further attacker action needed |
| **No Spoofing Required** | Unlike traditional cache poisoning (Kaminsky-style), this attack uses a completely legitimate response path — no IP spoofing, no TXID brute-forcing, no race conditions |

### Deployment Scenario

dnsmasq is extremely widely deployed as a lightweight DNS forwarder in:

- Home routers (OpenWrt, DD-WRT, Tomato)
- Container environments (Docker default DNS, libvirt)
- Embedded systems and IoT gateways
- Corporate LAN DNS forwarders

In these environments, dnsmasq typically forwards to upstream resolvers, and downstream clients directly trust dnsmasq's responses — making the bailiwick check bypass directly exploitable.

## Suggested Fix

1. **Bailiwick enforcement**: Before forwarding Authority/Additional section records, verify that each RRset's owner name is within the zone of the query (i.e., is a subdomain of the QNAME's zone cut). Discard any out-of-bailiwick records.

2. **Minimal response forwarding**: When acting as a forwarder, consider stripping Authority and Additional sections entirely for non-referral responses, forwarding only the Answer section.

3. Reference implementation: Technitium DNS Server's response sanitization logic can serve as a reference for correct bailiwick filtering behavior.

## References

- [RFC 2181 §5.4.1 — Ranking Data](https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1)
- [RFC 5452 §6 — Measures to Prevent DNS Cache Poisoning](https://datatracker.ietf.org/doc/html/rfc5452#section-6)
- [CVE-2021-25220 — BIND9 bailiwick check bypass](https://nvd.nist.gov/vuln/detail/CVE-2021-25220)
- [CVE-2025-11411 — Unbound bailiwick check bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-11411)
- [CVE-2022-32983 — Knot Resolver bailiwick check bypass](https://nvd.nist.gov/vuln/detail/CVE-2022-32983)

## PoC Repository

**All reproduction scripts, attack server, automated test, and detailed threat model:**

 **https://github.com/APEvul-cyber/dns_dnsmasq_vul/tree/main/Spoofed_Response_Authority_NS_RDATA_response**

## Test Environment

| Software                | Version       | Role                                    |
| ----------------------- | ------------- | --------------------------------------- |
| dnsmasq                 | 2.91          | Target (forwarding resolver)            |
| Technitium DNS Server   | 14.3          | Control group (correct behavior)        |
| BIND9                   | 9.20          | Legitimate authoritative for victim.lab |
| dnspython               | 2.7+          | Test script dependency                  |
| Docker / Docker Compose | Latest        | Container orchestration                 |
| OS                      | macOS / Linux | Host                                    |