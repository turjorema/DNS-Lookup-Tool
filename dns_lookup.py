#!/usr/bin/env python3
"""
DNS Lookup Tool
Developed by: 4rch-M4g

A standalone DNS client that builds and parses DNS packets itself, so it
needs nothing beyond the Python standard library.

Supports: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA
Features: custom resolver, UDP with automatic TCP fallback, reverse lookups,
          multi-record "--all" mode, propagation check across public
          resolvers, response timing, JSON output.

Usage:
    python dns_lookup.py example.com
    python dns_lookup.py example.com -t MX
    python dns_lookup.py example.com -t A AAAA TXT
    python dns_lookup.py example.com --all
    python dns_lookup.py 8.8.8.8                  # automatic reverse lookup
    python dns_lookup.py example.com -s 1.1.1.1   # choose resolver
    python dns_lookup.py example.com --propagation
    python dns_lookup.py example.com --all --json
"""

import argparse
import ipaddress
import json
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

__author__ = "4rch-M4g"
__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
RECORD_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257,
}
TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
          3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
ALL_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

PUBLIC_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

USE_COLOR = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


BANNER = r"""
  ____  _   _ ____    _                _
 |  _ \| \ | / ___|  | |    ___   ___ | | ___   _ _ __
 | | | |  \| \___ \  | |   / _ \ / _ \| |/ / | | | '_ \
 | |_| | |\  |___) | | |__| (_) | (_) |   <| |_| | |_) |
 |____/|_| \_|____/  |_____\___/ \___/|_|\_\\__,_| .__/
   DNS Lookup Tool                                |_|
   Developed by: 4rch-M4g
"""


class DNSError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Packet building / parsing
# --------------------------------------------------------------------------- #
def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        if len(raw) > 63:
            raise DNSError(f"Label too long: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype):
    txid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD flag set
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    return txid, header + question


def read_name(data, offset):
    """Decode a (possibly compressed) domain name. Returns (name, next_offset)."""
    labels, jumped, end, hops = [], False, offset, 0
    while True:
        if offset >= len(data):
            raise DNSError("Malformed packet (name overrun)")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise DNSError("Malformed packet (bad pointer)")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = pointer, True
            hops += 1
            if hops > 50:
                raise DNSError("Compression loop detected")
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        end = offset
    return (".".join(labels) or "."), end


def parse_rdata(rtype, data, offset, rdlen):
    end = offset + rdlen
    if rtype == 1 and rdlen == 4:
        return str(ipaddress.IPv4Address(data[offset:end]))
    if rtype == 28 and rdlen == 16:
        return str(ipaddress.IPv6Address(data[offset:end]))
    if rtype in (2, 5, 12):
        return read_name(data, offset)[0]
    if rtype == 15:
        pref = struct.unpack("!H", data[offset:offset + 2])[0]
        return f"{pref} {read_name(data, offset + 2)[0]}"
    if rtype == 16:
        parts, pos = [], offset
        while pos < end:
            ln = data[pos]
            parts.append(data[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
            pos += 1 + ln
        return "".join(parts)
    if rtype == 6:
        mname, pos = read_name(data, offset)
        rname, pos = read_name(data, pos)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos:pos + 20])
        return (f"{mname} {rname} serial={serial} refresh={refresh} "
                f"retry={retry} expire={expire} minimum={minimum}")
    if rtype == 33:
        prio, weight, port = struct.unpack("!HHH", data[offset:offset + 6])
        return f"{prio} {weight} {port} {read_name(data, offset + 6)[0]}"
    if rtype == 257:
        flags, taglen = data[offset], data[offset + 1]
        tag = data[offset + 2:offset + 2 + taglen].decode("ascii", "replace")
        value = data[offset + 2 + taglen:end].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"'
    return data[offset:end].hex()


def parse_response(data, txid):
    if len(data) < 12:
        raise DNSError("Response too short")
    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        raise DNSError("Transaction ID mismatch")
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4

    def read_records(count, offset):
        records = []
        for _ in range(count):
            name, offset = read_name(data, offset)
            rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            records.append({
                "name": name,
                "type": TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                "ttl": ttl,
                "data": parse_rdata(rtype, data, offset, rdlen),
            })
            offset += rdlen
        return records, offset

    answers, offset = read_records(an, offset)
    authority, offset = read_records(ns, offset)
    return {
        "rcode": RCODES.get(flags & 0x0F, f"RCODE{flags & 0x0F}"),
        "truncated": bool(flags & 0x0200),
        "authoritative": bool(flags & 0x0400),
        "recursion_available": bool(flags & 0x0080),
        "answers": answers,
        "authority": authority,
    }


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
def _family(server):
    return socket.AF_INET6 if ":" in server else socket.AF_INET


def query_udp(server, packet, timeout, port=53):
    with socket.socket(_family(server), socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        return s.recvfrom(4096)[0]


def query_tcp(server, packet, timeout, port=53):
    with socket.socket(_family(server), socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, port))
        s.sendall(struct.pack("!H", len(packet)) + packet)
        header = s.recv(2)
        if len(header) < 2:
            raise DNSError("TCP response truncated")
        length = struct.unpack("!H", header)[0]
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data


def resolve(name, rtype_name, server, timeout=4.0, force_tcp=False, port=53):
    """Run one DNS query. Returns a result dict (never raises for network errors)."""
    rtype = RECORD_TYPES[rtype_name]
    result = {"name": name, "type": rtype_name, "server": server}
    try:
        txid, packet = build_query(name, rtype)
        start = time.perf_counter()
        if force_tcp:
            raw, proto = query_tcp(server, packet, timeout, port), "TCP"
        else:
            raw, proto = query_udp(server, packet, timeout, port), "UDP"
        parsed = parse_response(raw, txid)
        if parsed["truncated"] and not force_tcp:
            raw, proto = query_tcp(server, packet, timeout, port), "TCP"
            parsed = parse_response(raw, txid)
        result.update(parsed)
        result["protocol"] = proto
        result["time_ms"] = round((time.perf_counter() - start) * 1000, 1)
    except socket.timeout:
        result["error"] = f"Timed out after {timeout}s"
    except (OSError, DNSError, struct.error, UnicodeError) as e:
        result["error"] = str(e)
    return result


def system_resolver():
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return "8.8.8.8"


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_result(res):
    head = f"{res['type']} record(s) for {res['name']}  @ {res['server']}"
    print(c(f"\n  [ {head} ]", "1;33"))

    if "error" in res:
        print(c(f"    [!] {res['error']}", "31"))
        return

    rcode_color = "32" if res["rcode"] == "NOERROR" else "31"
    flags = [f for f, on in (("aa", res["authoritative"]),
                             ("ra", res["recursion_available"])) if on]
    print(c(f"    status: {res['rcode']}  via {res['protocol']}  "
            f"{res['time_ms']} ms  flags: {' '.join(flags) or '-'}", rcode_color))

    if not res["answers"]:
        print(c("    No records found.", "90"))
    for rec in res["answers"]:
        print(f"    {c(rec['name'].ljust(28), '36')} "
              f"{c(str(rec['ttl']).rjust(6), '90')}  "
              f"{c(rec['type'].ljust(6), '35')} {rec['data']}")
    if not res["answers"] and res["authority"]:
        for rec in res["authority"]:
            print(c(f"    (authority) {rec['type']}: {rec['data']}", "90"))


def print_propagation(name, rtype, results):
    print(c(f"\n  [ Propagation check: {rtype} {name} ]", "1;33"))
    answer_sets = []
    for provider, res in results.items():
        if "error" in res:
            line, answers = c(f"error: {res['error']}", "31"), None
        elif res["rcode"] != "NOERROR":
            line, answers = c(res["rcode"], "31"), None
        else:
            answers = sorted(r["data"] for r in res["answers"])
            line = ", ".join(answers) if answers else c("no records", "90")
            line += c(f"  ({res['time_ms']} ms)", "90")
        answer_sets.append(tuple(answers) if answers is not None else None)
        print(f"    {c(provider.ljust(11), '36')} {PUBLIC_RESOLVERS[provider].ljust(16)} {line}")
    valid = [a for a in answer_sets if a is not None]
    if valid and len(set(valid)) == 1 and len(valid) == len(answer_sets):
        print(c("\n    Consistent: all resolvers agree.", "32"))
    else:
        print(c("\n    Differences or failures detected (may still be propagating, "
                "or the record uses geo/load-balanced answers).", "33"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="dns_lookup",
        description=f"DNS Lookup Tool - developed by {__author__}")
    p.add_argument("target", help="domain name, or an IP address for reverse lookup")
    p.add_argument("-t", "--type", nargs="+", default=None, metavar="TYPE",
                   help=f"record type(s): {', '.join(RECORD_TYPES)} (default: A)")
    p.add_argument("-a", "--all", action="store_true",
                   help=f"query common types: {', '.join(ALL_TYPES)}")
    p.add_argument("-s", "--server", help="resolver IP (default: system resolver)")
    p.add_argument("--port", type=int, default=53, help="resolver port (default 53)")
    p.add_argument("--tcp", action="store_true", help="force TCP instead of UDP")
    p.add_argument("--timeout", type=float, default=4.0, help="seconds per query (default 4)")
    p.add_argument("-p", "--propagation", action="store_true",
                   help="compare answers from Google, Cloudflare, Quad9 and OpenDNS")
    p.add_argument("-j", "--json", action="store_true", help="output JSON")
    p.add_argument("--save", metavar="FILE", help="save results to a JSON file")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-v", "--version", action="version",
                   version=f"%(prog)s {__version__} by {__author__}")
    return p


def main():
    global USE_COLOR
    args = build_parser().parse_args()
    if args.no_color or args.json:
        USE_COLOR = False

    target = args.target.strip().rstrip(".")
    types = [t.upper() for t in (args.type or [])]
    bad = [t for t in types if t not in RECORD_TYPES]
    if bad:
        print(f"Unsupported record type(s): {', '.join(bad)}. "
              f"Supported: {', '.join(RECORD_TYPES)}", file=sys.stderr)
        return 1

    # Reverse lookup for IP input
    try:
        ip = ipaddress.ip_address(target)
        target = ip.reverse_pointer
        types = ["PTR"]
        reverse_note = f"Reverse lookup for {ip}"
    except ValueError:
        reverse_note = None
        if args.all:
            types = ALL_TYPES
        elif not types:
            types = ["A"]

    server = args.server or system_resolver()
    if not args.json:
        print(c(BANNER, "1;35"))
        print(c(f"  Target: {args.target}   Resolver: {server}", "1;32"))
        if reverse_note:
            print(c(f"  {reverse_note} -> {target}", "34"))

    output = {"target": args.target, "queries": [], "propagation": None}

    # Propagation mode
    if args.propagation:
        rtype = types[0]
        with ThreadPoolExecutor(max_workers=len(PUBLIC_RESOLVERS)) as pool:
            futures = {name: pool.submit(resolve, target, rtype, ip, args.timeout,
                                         args.tcp, 53)
                       for name, ip in PUBLIC_RESOLVERS.items()}
            prop = {name: f.result() for name, f in futures.items()}
        output["propagation"] = prop
        if not args.json:
            print_propagation(target, rtype, prop)
    else:
        for rtype in types:
            res = resolve(target, rtype, server, args.timeout, args.tcp, args.port)
            output["queries"].append(res)
            if not args.json:
                print_result(res)

    if args.json:
        print(json.dumps(output, indent=2))
    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8") as fh:
                json.dump(output, fh, indent=2)
            if not args.json:
                print(c(f"\n  Results saved to {args.save}", "32"))
        except OSError as e:
            print(f"Could not save results: {e}", file=sys.stderr)
            return 1
    if not args.json:
        print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)