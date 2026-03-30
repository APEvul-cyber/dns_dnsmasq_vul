# PoC Report: Authority NS (out-of-bailiwick) in forwarded DNS responses

## Summary

This lab tests whether a DNS forwarder strips **out-of-bailiwick NS records** in the **Authority** section of an otherwise legitimate upstream response. The upstream is a **real** authoritative server for a zone the forwarder is configured to use (e.g. conditional forward). No off-path spoofing or transaction-ID guessing is required.

## Affected software (lab versions)

| Software    | Version | Authority NS filtering | Notes |
| ----------- | ------- | ---------------------- | ----- |
| Technitium  | v14.3   | Yes                    | Malicious Authority NS not relayed |
| dnsmasq     | v2.91   | No                     | Malicious Authority NS relayed to clients; dnsmasq does not cache Authority RRs itself, but stubs or a downstream recursive may be misled or poisoned in chained setups |

## Suggested CVE-style description (English)

When dnsmasq forwards queries to an upstream that is the real authoritative server for a delegated zone, it may return the upstream’s full response—including NS records in the Authority section for unrelated zones (out-of-bailiwick)—to local clients without stripping them. The reply is a genuine answer to a query dnsmasq sent, so normal response-matching checks apply; the issue is missing bailiwick/relevance filtering on Authority data. Dnsmasq may not cache those NS records itself, but relaying them can still mislead stubs or contribute to poisoning if a downstream caching resolver accepts them. Lab observation: dnsmasq 2.91; other versions not verified.

## Reproduction

See `README.md` in this directory: `run_full_test.sh`, `malicious_auth_server.py`, and `test_cache_poison.py`.

## Disclaimer

For security research only. Run in an isolated lab.
