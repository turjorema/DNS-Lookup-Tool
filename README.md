# DNS Lookup Tool

> **Developed by 4rch-M4g**

A fast, dependency-free DNS lookup utility written in pure Python. It builds and parses DNS packets itself (no `dnspython`, no `dig`, no `nslookup`), so it runs anywhere Python 3 runs.

```
  ____  _   _ ____    _                _
 |  _ \| \ | / ___|  | |    ___   ___ | | ___   _ _ __
 | | | |  \| \___ \  | |   / _ \ / _ \| |/ / | | | '_ \
 | |_| | |\  |___) | | |__| (_) | (_) |   <| |_| | |_) |
 |____/|_| \_|____/  |_____\___/ \___/|_|\_\\__,_| .__/
   DNS Lookup Tool                                |_|
   Developed by: 4rch-M4g
```

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Options](#options)
- [Supported Record Types](#supported-record-types)
- [Examples](#examples)
- [JSON Output](#json-output)
- [How It Works](#how-it-works)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Features

- **10 record types:** A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA
- **Reverse lookups:** give it an IP address and it automatically runs a PTR query
- **`--all` mode:** query all the common record types for a domain in one command
- **Custom resolver:** choose any DNS server (`-s 1.1.1.1`) and port, or use your system resolver
- **UDP with automatic TCP fallback:** truncated responses are retried over TCP; `--tcp` forces TCP
- **Propagation check:** compare answers from Google, Cloudflare, Quad9 and OpenDNS side by side
- **Response details:** status code (NOERROR, NXDOMAIN, SERVFAIL...), response time, TTL, and `aa`/`ra` flags
- **JSON output:** machine-readable results and a `--save` option
- **Zero dependencies:** Python standard library only
- **Colored terminal output** (auto-disabled when piped or with `--no-color`)

## Requirements

- Python **3.7+**
- Network access to a DNS resolver (UDP/TCP port 53)
- Works on Linux, macOS and Windows

## Installation

No installation is needed. Download the script and run it:

```bash
git clone <your-repo-url>
cd <your-repo>
python dns_lookup.py example.com
```

Or simply save `dns_lookup.py` anywhere and run it. On Linux/macOS you can make it executable:

```bash
chmod +x dns_lookup.py
./dns_lookup.py example.com
```

## Quick Start

```bash
python dns_lookup.py example.com              # A record
python dns_lookup.py example.com -t MX        # mail servers
python dns_lookup.py example.com --all        # everything common
python dns_lookup.py 8.8.8.8                  # reverse lookup
python dns_lookup.py example.com -p           # propagation check
```

## Usage

```
python dns_lookup.py <target> [options]
```

`<target>` can be a **domain name** or an **IP address** (IPv4 or IPv6). IP addresses trigger a reverse (PTR) lookup automatically.

## Options

| Option | Description |
|---|---|
| `-t`, `--type TYPE [TYPE ...]` | One or more record types (default: `A`) |
| `-a`, `--all` | Query A, AAAA, CNAME, MX, NS, TXT, SOA and CAA |
| `-s`, `--server IP` | Resolver to use (default: system resolver, fallback `8.8.8.8`) |
| `--port N` | Resolver port (default: `53`) |
| `--tcp` | Force TCP instead of UDP |
| `--timeout SECONDS` | Timeout per query (default: `4`) |
| `-p`, `--propagation` | Compare answers across Google, Cloudflare, Quad9 and OpenDNS |
| `-j`, `--json` | Output results as JSON |
| `--save FILE` | Save results to a JSON file |
| `--no-color` | Disable colored output |
| `-v`, `--version` | Show version and author |
| `-h`, `--help` | Show help |

## Supported Record Types

| Type | Meaning | Output format |
|---|---|---|
| `A` | IPv4 address | `93.184.216.34` |
| `AAAA` | IPv6 address | `2606:2800:220:1:...` |
| `CNAME` | Canonical name (alias) | `target.example.com` |
| `MX` | Mail exchanger | `10 mail.example.com` |
| `NS` | Name server | `ns1.example.com` |
| `TXT` | Text (SPF, DKIM, verification) | `v=spf1 -all` |
| `SOA` | Start of authority | primary NS, admin, serial, timers |
| `PTR` | Reverse pointer | `dns.google` |
| `SRV` | Service locator | `priority weight port target` |
| `CAA` | Certificate authority authorization | `0 issue "letsencrypt.org"` |

## Examples

### Basic lookup
```bash
python dns_lookup.py example.com
```

### Multiple record types
```bash
python dns_lookup.py example.com -t A AAAA MX TXT
```

### Reverse lookup
```bash
python dns_lookup.py 8.8.8.8
```
```
  [ PTR record(s) for 8.8.8.8.in-addr.arpa  @ 8.8.8.8 ]
    status: NOERROR  via UDP  3.3 ms  flags: ra
    8.8.8.8.in-addr.arpa          13504  PTR    dns.google
```

### Use a specific resolver
```bash
python dns_lookup.py example.com -s 1.1.1.1
```

### Look up a service record
```bash
python dns_lookup.py _sip._tcp.example.com -t SRV
```

### Check DNS propagation
Useful after you change a record, to see whether the major public resolvers agree:
```bash
python dns_lookup.py example.com -t A --propagation
```
The tool reports **Consistent** if every resolver returns the same answers, or flags differences. Note that CDN and load-balanced domains may legitimately return different answers per resolver.

### Force TCP
```bash
python dns_lookup.py example.com --tcp
```

### Save results
```bash
python dns_lookup.py example.com --all --save results.json
```

## JSON Output

Use `--json` for scripting:

```bash
python dns_lookup.py example.com -t A --json
```

```json
{
  "target": "example.com",
  "queries": [
    {
      "name": "example.com",
      "type": "A",
      "server": "8.8.8.8",
      "rcode": "NOERROR",
      "truncated": false,
      "authoritative": false,
      "recursion_available": true,
      "answers": [
        { "name": "example.com", "type": "A", "ttl": 300, "data": "93.184.216.34" }
      ],
      "authority": [],
      "protocol": "UDP",
      "time_ms": 12.4
    }
  ],
  "propagation": null
}
```

Network failures never crash the tool; they appear as an `"error"` field on the affected query.

## How It Works

1. Builds a standards-compliant DNS query packet (header + question) with a random transaction ID.
2. Sends it over UDP to the chosen resolver and verifies the transaction ID of the reply.
3. If the response is flagged as truncated, repeats the query over TCP automatically.
4. Parses the answer and authority sections, including **compressed domain names**, and decodes each record type into readable text.

## Limitations

- **No DNSSEC validation:** DNSSEC record types are not decoded.
- **Unsupported record types** that appear in a response are shown as raw hex.
- **Recursive queries only:** the tool asks resolvers to recurse (RD flag) and does not walk the DNS tree from the root itself.
- **No DNS-over-HTTPS/TLS:** queries use classic DNS on port 53.
- The system resolver is read from `/etc/resolv.conf`; on Windows or when that file is missing, `8.8.8.8` is used unless you pass `-s`.

## Troubleshooting

| Problem | Likely cause / fix |
|---|---|
| `Timed out after 4.0s` | Resolver unreachable or port 53 blocked. Try `-s 1.1.1.1`, `--tcp`, or a longer `--timeout`. |
| `status: NXDOMAIN` | The domain does not exist (check spelling). |
| `status: SERVFAIL` | The resolver could not get an answer. Retry with a different `-s` server. |
| `status: REFUSED` | The resolver does not allow queries from you. Use a public resolver. |
| `No records found` | The name exists, but has no record of that type. |
| `Unsupported record type` | Use one of: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA. |
| Garbled colors on Windows | Run with `--no-color`, or use Windows Terminal. |

## Disclaimer

This tool performs standard DNS queries and is intended for network administration, troubleshooting, education and authorized security work. Only query systems and use resolvers you are permitted to use. The author is not responsible for misuse.

## Author

**4rch-M4g**

Contributions, ideas and bug reports are welcome. Add a `LICENSE` file of your choice before publishing the project.
