# 🛡️ tls-scan — TLS/SSL Verification and Tracing Tool

[![Build Status](https://github.com/byteherders/tls-scan/actions/workflows/go.yml/badge.svg)](https://github.com/byteherders/tls-scan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/byteherders/tls-scan)](https://goreportcard.com/report/github.com/byteherders/tls-scan)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-lightgrey.svg)](https://github.com/sponsors/byteherders)

### 🔍 Overview

`tls-scan` is a fast, lightweight Go tool for verifying SSL/TLS configurations.  
It checks certificate chains, expiry dates, weak protocols and ciphers, OCSP stapling, and HSTS headers — then summarizes the results in clean, human-readable or JSON form.

Perfect for sysadmins, red-teamers, and anyone who doesn’t want to get surprised by expired or misconfigured certificates.

## 🚀 Features

- Full TLS handshake with SNI and version detection  
- Certificate chain validation using system or custom CA bundles  
- Expiry and weak cipher warnings  
- Optional **OCSP stapling** parsing  
- Optional **HSTS** probing via HTTPS request  
- Configurable grading system (1–5) via YAML policy file  
- Fast concurrent scanning  
- JSON or pretty output  
- Self-contained binary — no dependencies, no nonsense  

## 🧰 Installation

```bash
git clone https://github.com/byteherders/tls-scan.git
cd tls-scan
go build -o tls-scan ./cmd/tls-scan
```

Or download a prebuilt binary from [Releases](https://github.com/byteherders/tls-scan/releases).

## ⚙️ Usage

Run without arguments to show all available flags:

```bash
./tls-scan
```

Typical usage:

```bash
# Basic scan
./tls-scan example.com

# Scan multiple hosts, output as JSON
./tls-scan --json example.com www.cloudflare.com

# Include HSTS probe and tighter timeout
./tls-scan --hsts --timeout 3s example.com

# Use a custom policy for grading
./tls-scan --policy ./policy.yaml example.com
```

### Available Flags

| Flag | Description |
|------|--------------|
| `--timeout` | Per-target timeout (default: 5s) |
| `--json` | Output machine-readable JSON |
| `--port` | Default port if none specified (default: 443) |
| `--ca-bundle` | Load a custom CA bundle (PEM format) |
| `--concurrency` | Number of parallel scans (default: 10) |
| `--hsts` | Perform HTTPS GET / to detect HSTS header |
| `--policy` | Path to YAML file defining grading rules |
| `--help` | Show usage instructions |

## 📊 Example Output

### Human-readable
```
=== example.com ===
TLS: TLS1.3  Cipher: TLS_AES_256_GCM_SHA384  ALPN: h2  SNI: example.com  Grade: 1/5
Leaf: CN=example.com → CN=DigiCert TLS RSA SHA256 2020 CA1  Expires: 2026-09-15T12:00:00Z (in 24972h0m0s)
OCSP: good  nextUpdate=2025-12-01T00:00:00Z
HSTS: present max-age=31536000 includeSubDomains=true preload=true
Risks: none
```

### JSON
```bash
./tls-scan --json example.com | jq
```

```json
[
  {
    "target": "example.com",
    "tls": {
      "version": "TLS1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "alpn": "h2",
      "server_name": "example.com"
    },
    "grade": 1,
    "risks": []
  }
]
```

## 📜 Custom Grading Policy

You can define your own grading thresholds and weights in YAML:

```yaml
weights:
  EXPIRY_SOON_CRIT: 50
  WEAK_CIPHER: 30
  HSTS_MISSING: 10
bands:
  - { min: 0,  max: 10,  grade: 1 }
  - { min: 11, max: 30,  grade: 2 }
  - { min: 31, max: 60,  grade: 3 }
  - { min: 61, max: 90,  grade: 4 }
  - { min: 91, max: 999, grade: 5 }
```

Then:
```bash
./tls-scan --policy ./policy.yaml example.com
```

## 🧪 Build & Test

```bash
go test ./...
```

GitHub Actions CI runs on every push:

![Build](https://github.com/byteherders/tls-scan/actions/workflows/go.yml/badge.svg

## 💖 Support Development

If tls-scan saved you from another 3 AM certificate panic — maybe buy me a coffee.

- ☕ [Sponsor via GitHub](https://github.com/sponsors/byteherders)  
- 💰 [PayPal.me/yourhandle](https://paypal.me/byteherder)  
- 🧡 [Ko-fi](https://ko-fi.com/byteherder)

Every bit keeps the caffeine flowing and the code linted.

## 🧑‍💻 License

MIT License © [Tom Herder of Byteherder](https://github.com/byteherders)

### TL;DR
One binary, full TLS sanity check.  
Run it, read it, sleep better.
