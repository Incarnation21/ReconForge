# ReconForge 🔍

**Modular Offensive Reconnaissance & Continuous Attack Surface Monitoring Framework — Python 3.11+**

> ⚠️ **LEGAL NOTICE:** ReconForge is designed exclusively for authorized security testing, penetration testing, and authorized bug bounty hunting. Only scan systems you own or have **explicit written permission** to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

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
   └── Stage 6: tech_fingerprint + dir_enum + tls_inspect + takeover (parallel)
         │
         ├── [SAN Feedback Loop → ip_resolve → portscan]
         │
         ▼
[Continuous State Database (SQLite) & Delta Diff Engine]
   │
   ├── [Push Notifications → Discord / Slack / Telegram Webhooks]
   └── [Dual Reporting → JSON Schema + Standalone Dark-Mode HTML]
```

## Modules

| Module | Capability |
|---|---|
| `dns_enum` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records, AXFR zone transfer attempt, SPF/DMARC email security |
| `subdomain` | Passive CT logs (crt.sh) + Active wordlist brute-force with wildcard DNS suppression |
| `ip_resolve` | A/AAAA forward resolution, PTR reverse lookup, shared-IP multi-tenant grouping |
| `portscan` | Native async TCP connect scanner, service banner grabbing, top-1000 ports |
| `whois_rdap` | RDAP (REST) + port-43 WHOIS fallback for domain and IP/ASN data |
| `http_probe` | Multi-redirect following, security header audit, title/server extraction |
| `tech_fingerprint` | Headers, cookies, HTML regex, meta-generator, favicon MurmurHash3 (Shodan-style) |
| `dir_enum` | Soft-404 baseline calibration, sensitive path detection (`.git`, `.env`, `phpinfo.php`...) |
| `tls_inspect` | X.509 cert parsing, expiry checking, legacy protocol/cipher detection, SAN extraction |
| `takeover` | Dangling CNAME pointer verification and subdomain takeover detection against 12+ cloud providers (AWS S3, GitHub Pages, Heroku, Azure, Shopify, etc.) |

---

## Continuous Monitoring & Webhook Alerts

ReconForge includes advanced capabilities for modern red team operations and bug bounty automation:

### 1. Subdomain Takeover Auditing (`takeover`)
Checks CNAME records against high-fidelity provider fingerprints (e.g. `NoSuchBucket`, `There isn't a GitHub Pages site here`, `No such app`) and verifies dangling pointers where the CNAME target returns `NXDOMAIN`.

### 2. Attack Surface State Diffing (`reconforge diff`)
Tracks target history in a lightweight SQLite database (`reconforge_history.db`) to identify **attack surface deltas**:
- Newly discovered subdomains/hosts (`+`)
- Decommissioned/unresponsive hosts (`-`)
- Newly opened ports on active infrastructure
- Closed ports
- Newly introduced security vulnerabilities
- Web service HTTP status code shifts (`403 Forbidden -> 200 OK`)

```bash
# Compare against the previous scan during active recon
reconforge target.com --authorized --diff

# Inspect historical scans
reconforge diff --list

# Compute diff between the 2 most recent scans of a target
reconforge diff --target target.com

# Compare two arbitrary scan IDs
reconforge diff 7b4e39a8 a1f2c3d4
```

### 3. Real-Time Webhook Alerts
Sends instant push alerts for **CRITICAL / HIGH** severity findings (e.g., Subdomain Takeovers, exposed credentials) as well as end-of-scan summaries with rich formatting:
- **Discord**: Color-coded embedded messages with severity sidebars and evidence snippets.
- **Slack**: Block attachments formatted for security channel triage.
- **Telegram**: HTML-formatted messages with direct mobile notifications.
- **Generic JSON**: Structured HTTP POST payload for CI/CD or SIEM ingestion.

```bash
# Discord webhook
reconforge target.com --authorized --webhook "https://discord.com/api/webhooks/..."

# Telegram bot integration
reconforge target.com --authorized --webhook "telegram:<BOT_TOKEN>:<CHAT_ID>"
```

---

## Installation

```bash
cd reconforge

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies and ReconForge
pip install -e ".[dev]"
```

## Quick Start

```bash
# Basic domain scan (--authorized is MANDATORY)
reconforge example.com --authorized

# Enable continuous monitoring diff against previous scan
reconforge example.com --authorized --diff

# Real-time alert dispatch to Discord/Slack
reconforge example.com --authorized --webhook https://discord.com/api/webhooks/...

# Targeted module scan
reconforge example.com --authorized -m dns_enum subdomain takeover portscan

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

Output & Integrations:
  -o DIR                    Output directory (default: .)
  -f FMT [...]              json html (default: both)
  --webhook URL             Discord, Slack, Telegram, or JSON webhook endpoint
  --diff                    Compute and display delta diff against target's previous scan
  --db-path PATH            Path to SQLite history database (default: reconforge_history.db)
  -v                        Verbose logging
```

## Project Structure

```
reconforge/
├── reconforge/
│   ├── cli.py                  # CLI entry point, scan & diff commands
│   ├── core/
│   │   ├── models.py           # Typed data classes (Target, Finding, ScanResult...)
│   │   ├── scope.py            # Scope validation & target normalization
│   │   ├── context.py          # Shared ScanContext & ScanConfig
│   │   ├── store.py            # Thread-safe ResultStore
│   │   ├── limiter.py          # Token-bucket rate limiter
│   │   ├── module.py           # BaseModule & registration system
│   │   ├── orchestrator.py     # DAG pipeline orchestrator
│   │   └── diff_engine.py      # SQLite state database & continuous diff engine
│   ├── modules/
│   │   ├── dns_enum.py         # DNS enumeration & SPF/DMARC
│   │   ├── subdomain.py        # CT logs & active brute-force
│   │   ├── ip_resolve.py       # IP & PTR resolution
│   │   ├── portscan.py         # Async TCP connect scanner
│   │   ├── whois_rdap.py       # RDAP & WHOIS queries
│   │   ├── http_probe.py       # HTTP probing & security headers
│   │   ├── tech_fingerprint.py # Fingerprinting & Murmur3 hash
│   │   ├── dir_enum.py         # Soft-404 calibrated directory enum
│   │   ├── tls_inspect.py      # TLS audit & SAN extraction
│   │   └── takeover.py         # Dangling CNAME & subdomain takeover
│   └── reporting/
│       ├── json_report.py      # Machine-readable JSON
│       ├── html_report.py      # Standalone interactive dark-mode HTML
│       └── webhook.py          # Discord / Slack / Telegram notifier
├── wordlists/
│   └── subdomains.txt
├── tests/
│   ├── test_core.py
│   ├── test_diff_engine.py
│   ├── test_reporting.py
│   ├── test_takeover.py
│   ├── test_utils.py
│   └── test_webhook.py
├── pyproject.toml
└── README.md
```

## Ethical Use

ReconForge includes mandatory ethical guardrails:
- `--authorized` flag is **required** — the scan will not start without it
- Private RFC1918 ranges are **blocked by default** — requires `--allow-private`
- Non-destructive HTTP methods only (`GET`/`HEAD`/`OPTIONS`)
- Built-in token bucket rate limiting to prevent target disruption

## License

MIT License — See [LICENSE](LICENSE) for details.
