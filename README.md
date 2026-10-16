# ReconForge 🔍

**Modular Reconnaissance Framework — Python 3.11+**

> ⚠️ **LEGAL NOTICE:** ReconForge is designed exclusively for authorized security testing. Only scan systems you own or have **explicit written permission** to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

---

## Architecture

```
Target Input (Domain / IP / CIDR / URL)
   │
   ▼
[Scope Enforcement & Target Normalization]
   │
   ▼
[DAG Orchestrator - Stage Pipeline]
   ├── Stage 1: dns_enum
   ├── Stage 2: subdomain + whois_rdap (parallel)
   ├── Stage 3: ip_resolve
   ├── Stage 4: portscan
   ├── Stage 5: http_probe
   └── Stage 6: tech_fingerprint + dir_enum + tls_inspect (parallel)
         │
         └── [SAN Feedback Loop → ip_resolve → portscan]
                   │
                   ▼
         [JSON + HTML Reports]
```

## Features

| Module | Capability |
|---|---|
| `dns_enum` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records, AXFR zone transfer attempt, SPF/DMARC analysis |
| `subdomain` | Passive CT logs (crt.sh) + Active wordlist brute-force with wildcard suppression |
| `ip_resolve` | A/AAAA forward resolution, PTR reverse lookup, shared-IP grouping |
| `portscan` | Native async TCP connect scanner, service banner grabbing, top-1000 ports |
| `whois_rdap` | RDAP (REST) + port-43 WHOIS fallback for domain and IP/ASN data |
| `http_probe` | Multi-redirect following, security header audit, title/server extraction |
| `tech_fingerprint` | Headers, cookies, HTML regex, meta-generator, favicon MurmurHash3 (Shodan-style) |
| `dir_enum` | Soft-404 calibration, sensitive path detection (`.git`, `.env`, `phpinfo.php`...) |
| `tls_inspect` | X.509 cert parsing, expiry checking, legacy protocol/cipher detection, SAN extraction |

## Installation

```bash
cd reconforge

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install
pip install -e ".[dev]"
```

## Quick Start

```bash
# Basic domain scan (--authorized is MANDATORY)
reconforge example.com --authorized

# Targeted module scan
reconforge example.com --authorized -m dns_enum subdomain portscan

# Full scan with custom rate and output directory
reconforge example.com --authorized --rate 50 --timeout 10 -o ./reports

# IP range scan (CIDR - use only on networks you own)
reconforge 192.168.1.0/24 --authorized --allow-private

# Skip directory enumeration
reconforge example.com --authorized --skip-modules dir_enum

# Verbose output with custom ports
reconforge example.com --authorized --ports 80,443,8080,8443 -v
```

## CLI Reference

```
usage: reconforge TARGET --authorized [options]

Required:
  TARGET                    Domain, IP, CIDR, or URL
  --authorized              Confirm explicit authorization [REQUIRED]

Scope:
  --scope-file FILE         Allowed domains/CIDRs file
  --allow-private           Allow private RFC1918 ranges

Modules:
  --modules MODULE [...]    Only run specified modules
  --skip-modules MODULE     Skip specified modules

Network:
  --rate N                  Requests/sec (default: 100)
  --concurrency N           Max connections (default: 200)
  --timeout SEC             Connection timeout (default: 5)

Port Scanning:
  --ports SPEC              top100 | top1000 | all | 80,443,8080
  --nmap                    Enable Nmap secondary engine

Wordlists:
  -w FILE                   Subdomain wordlist
  --dir-wordlist FILE       Directory brute-force wordlist

Output:
  -o DIR                    Output directory (default: .)
  -f FMT [...]              json html (default: both)
  -v                        Verbose logging
```

## Project Structure

```
reconforge/
├── reconforge/
│   ├── cli.py                  # Entry point
│   ├── core/
│   │   ├── models.py           # Data classes (Target, Finding, ScanResult...)
│   │   ├── scope.py            # Scope validation & target normalization
│   │   ├── context.py          # Shared ScanContext & ScanConfig
│   │   ├── store.py            # Thread-safe ResultStore
│   │   ├── limiter.py          # Token-bucket rate limiter
│   │   ├── module.py           # BaseModule & registration system
│   │   └── orchestrator.py     # DAG pipeline orchestrator
│   ├── modules/
│   │   ├── dns_enum.py
│   │   ├── subdomain.py
│   │   ├── ip_resolve.py
│   │   ├── portscan.py
│   │   ├── whois_rdap.py
│   │   ├── http_probe.py
│   │   ├── tech_fingerprint.py
│   │   ├── dir_enum.py
│   │   └── tls_inspect.py
│   └── reporting/
│       ├── json_report.py
│       └── html_report.py
├── wordlists/
│   └── subdomains.txt
├── tests/
├── pyproject.toml
└── README.md
```

## Ethical Use

ReconForge includes mandatory ethical guardrails:
- `--authorized` flag is **required** — the scan will not start without it
- Private RFC1918 ranges are **blocked by default** — requires `--allow-private`
- Non-destructive HTTP methods only (`GET`/`HEAD`/`OPTIONS`)
- Built-in rate limiting to avoid target disruption

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success, no critical findings |
| 1 | Error (bad target, scope violation, missing arg) |
| 2 | Success but critical severity findings were found |

## License

MIT License — See [LICENSE](LICENSE) for details.
