# DugganUSA Threat Intel Scanner for VS Code

**Scan your code for threat indicators in real-time. 1,080,000+ IOCs. Cross-platform. Free.**

[![VS Code Marketplace](https://img.shields.io/badge/VS%20Code-Marketplace-blue?logo=visual-studio-code)](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![STIX Consumers](https://img.shields.io/badge/STIX%20Consumers-275%2B-brightgreen)](https://analytics.dugganusa.com/api/v1/stix-feed)

---

## What It Does

Every IP address, domain, SHA256 hash, and CVE ID in your code is a potential indicator of compromise. This extension finds them automatically and checks each one against the [DugganUSA threat intelligence index](https://analytics.dugganusa.com) — the same STIX 2.1 feed trusted by 275+ organizations across 46 countries, including Fortune 500 security teams.

**Open a file. Save a file. The scanner runs.** Known-bad indicators appear as inline warnings with enrichment details — malware family, threat type, source, and cross-index hit count. No context switching. No browser tabs. No copy-paste into VirusTotal. The intelligence is in your editor where the code already is.

### Example

You open a config file. Line 42 has a hardcoded IP: `185.39.19.176`. The extension highlights it:

> **DugganUSA: 185.39.19.176 — IOC: Cobalt Strike C2 (via SSLBL) | Blocked 47x | In 3 OTX pulse(s) (12 cross-index hits)**

Right-click, "View in DugganUSA" opens the full correlation in your browser.

---

## Who It's For

- **Security engineers** reviewing infrastructure code, Terraform configs, Ansible playbooks — catch hardcoded C2 IPs before they ship
- **SOC analysts** triaging incident reports — paste an indicator, get instant enrichment without leaving the editor
- **DevSecOps teams** building CI/CD pipelines — scan PRs for known-bad indicators as part of code review
- **Threat researchers** writing reports — validate IOCs inline while documenting
- **Anyone** who touches config files, log snippets, or threat intelligence data in VS Code

---

## Features

| Feature | Description |
|---------|-------------|
| **Auto-scan on save** | Every saved file is scanned for IOC patterns |
| **Auto-scan on open** | Files are checked when you open them |
| **Right-click lookup** | Select any text, right-click, "DugganUSA: Look Up Selected Text" |
| **Workspace scan** | Scan up to 50 files across your project in one command |
| **Inline diagnostics** | Yellow squiggly warnings with enrichment in the Problems panel |
| **Cross-index correlation** | Each indicator checked against IOCs, block events, OTX pulses, adversary profiles, CISA KEV, and more |
| **Smart filtering** | Skips known-safe IPs (localhost, DNS resolvers) and common domains |
| **5-minute cache** | Results cached locally to minimize API calls |
| **First-run setup** | Welcome walkthrough guides you through API key configuration |
| **Prerequisite checks** | Validates API connectivity and key format on activation |
| **Privacy-first** | Only IOC values are sent to the API — never source code, file paths, or file contents |
| **AIPM Audit** | Audit any domain's AI presence right inside VS Code — 5 models, 7 signals, 15 seconds |
| **STIX Feed access** | Browse STIX feed pricing and registration without leaving your editor |

---

## Getting Started

### 1. Install the Extension

**From VS Code:**
1. Open Extensions (Ctrl+Shift+X / Cmd+Shift+X)
2. Search for "DugganUSA Threat Intel"
3. Click Install

**From the command line:**
```bash
code --install-extension DugganUSALLC.dugganusa-threat-intel
```

For more on installing extensions, see the [VS Code Extension Marketplace docs](https://code.visualstudio.com/docs/editor/extension-marketplace).

### 2. Get Your API Key (Free)

Visit **[analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register)**. No credit card. No login. Takes 30 seconds.

The extension works without a key at reduced rate limits, but an API key unlocks full query volume.

### 3. Configure

Open VS Code Settings (Ctrl+, / Cmd+,) and search for "DugganUSA":

| Setting | Description | Default |
|---------|-------------|---------|
| `dugganusa.apiKey` | Your API key (`dugusa_...` format) | *(empty)* |
| `dugganusa.scanOnSave` | Auto-scan files when saved | `true` |
| `dugganusa.scanOnOpen` | Auto-scan files when opened | `true` |
| `dugganusa.apiUrl` | API base URL (change only for on-prem) | `https://analytics.dugganusa.com/api/v1` |

Or edit `settings.json`:

```json
{
  "dugganusa.apiKey": "dugusa_YOUR_KEY_HERE",
  "dugganusa.scanOnSave": true,
  "dugganusa.scanOnOpen": true
}
```

See [VS Code User and Workspace Settings](https://code.visualstudio.com/docs/getstarted/settings).

### 4. Start Coding

Open a file with IPs, domains, hashes, or CVEs. Check the **Problems panel** (Ctrl+Shift+M / Cmd+Shift+M).

---

## Commands

Open the **Command Palette** (Ctrl+Shift+P / Cmd+Shift+P):

| Command | Description |
|---------|-------------|
| `DugganUSA: Scan Current File` | Scan the active file now |
| `DugganUSA: Scan Entire Workspace` | Scan up to 50 project files |
| `DugganUSA: Look Up Selected Text` | Right-click or palette lookup |
| `DugganUSA: AIPM Audit` | Audit any domain's AI presence — opens inside VS Code |
| `DugganUSA: Open STIX Feed & Pricing` | Browse STIX feed tiers in-editor |

---

## What It Detects

| Pattern | Example | Detection |
|---------|---------|-----------|
| **IPv4** | `185.39.19.176` | Cobalt Strike C2, 12 hits |
| **Domains** | `welcome.supp0v3.com` | STX RAT C2, CPUID supply chain |
| **SHA256** | `52862b538459c8...` | STX RAT payload, 3 hits |
| **CVE IDs** | `CVE-2026-21643` | Fortinet EMS SQLi, CISA KEV |

---

## Pricing

The extension is **free and open source** (MIT). The API has tiered rate limits:

| Tier | Queries/Day | Price |
|------|------------|-------|
| **Free** | 500 | $0 |
| **Starter** | 1,000 | $45/mo |
| **Researcher** | 2,000 | $145/mo |
| **Professional** | 5,000 | $495/mo |
| **Medusa Suite** | 50,000 | $8,995/mo |
| **Enterprise** | Unlimited | $24,995/mo |

Register at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register).

---

## Prerequisites

- [VS Code](https://code.visualstudio.com/) 1.85+
- Internet connectivity (degrades gracefully offline)
- Free API key recommended

**Fully cross-platform** — no native dependencies. Works on:
Windows, macOS, Linux, [WSL](https://code.visualstudio.com/docs/remote/wsl), [Remote SSH](https://code.visualstudio.com/docs/remote/ssh), [GitHub Codespaces](https://code.visualstudio.com/docs/remote/codespaces), [vscode.dev](https://code.visualstudio.com/docs/editor/vscode-web).

---

## What's In The Index

**1,080,000+ indicators** from:

- [OTX AlienVault](https://otx.alienvault.com/user/pduggusa) (16,800+ pulses)
- [abuse.ch SSLBL](https://sslbl.abuse.ch/) + [URLhaus](https://urlhaus.abuse.ch/)
- [Spamhaus DROP/EDROP](https://www.spamhaus.org/drop/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (1,568 entries)
- DugganUSA original research (supply chain Pattern 38-48)
- Exploit harvester (84 rules, GitHub scanning every 6h)
- Edge honeypots (30 canary paths on Cloudflare Workers)

Cross-correlated across **44 indexes**.

Also available as [STIX 2.1 JSON](https://analytics.dugganusa.com/api/v1/stix-feed), [IP blocklist CSV](https://analytics.dugganusa.com/api/v1/stix-feed/ips.csv), [Domain CSV](https://analytics.dugganusa.com/api/v1/stix-feed/domains.csv), [Hash CSV](https://analytics.dugganusa.com/api/v1/stix-feed/hashes.csv).

---

## Privacy

- **Only IOC values** sent to the API — never source code, file paths, or workspace metadata
- **No telemetry** beyond API lookups
- **HTTPS only** (TLS 1.2+)
- **Local cache only** — never persisted to disk
- **Open source** — inspect the code

---

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, testing, and publishing.

```bash
git clone https://github.com/pduggusa/dugganusa-vscode.git
cd dugganusa-vscode
code .
# Press F5 to launch Extension Development Host
```

See [VS Code Extension API](https://code.visualstudio.com/api) and [Publishing Extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

---

## Links

| Resource | URL |
|----------|-----|
| VS Code Marketplace | [marketplace.visualstudio.com](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel) |
| GitHub | [github.com/pduggusa/dugganusa-vscode](https://github.com/pduggusa/dugganusa-vscode) |
| DugganUSA | [dugganusa.com](https://www.dugganusa.com) |
| AIPM Security | [aipmsec.com](https://aipmsec.com) |
| STIX Feed | [analytics.dugganusa.com/api/v1/stix-feed](https://analytics.dugganusa.com/api/v1/stix-feed) |
| API Registration | [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register) |
| Issues | [github.com/pduggusa/dugganusa-vscode/issues](https://github.com/pduggusa/dugganusa-vscode/issues) |

---

## License

[MIT](LICENSE) — DugganUSA LLC, Minneapolis, MN.

Built by two people, one AI partner, and $75/month in infrastructure.
