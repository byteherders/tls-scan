# 🛡️ TLS-Scan — TLS/SSL Verification and Tracing Tool

[![Build Status](https://github.com/byteherders/tls-scan/actions/workflows/go.yml/badge.svg)](https://github.com/byteherders/tls-scan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/byteherders/tls-scan)](https://goreportcard.com/report/github.com/byteherders/tls-scan)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-lightgrey.svg)](https://github.com/sponsors/byteherders)

### 🔍 Overview

`tls-scan` is a fast, lightweight Go tool for verifying SSL/TLS configurations.  
It checks certificate chains, expiry dates, weak protocols and ciphers, OCSP stapling, and HSTS headers — then summarizes the results in clean, human-readable or JSON form.

Perfect for anyone who doesn’t want to get surprised by expired or misconfigured certificates.

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
cd tlscan
go build -o tlscan ./cmd/tlscan
```
