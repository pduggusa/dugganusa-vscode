# Changelog

## 0.2.0 (2026-04-17)

### New Features

- **AIPM Audit command** — `DugganUSA: AIPM Audit — How Does AI See This Domain?` opens an AIPM audit directly inside VS Code. Enter any domain, get a 5-model AI perception score with 7-signal structure analysis. No browser needed — the audit runs in a VS Code tab via Simple Browser. Falls back to external browser if Simple Browser is unavailable.
- **STIX Feed command** — `DugganUSA: Open STIX Feed & Pricing` opens the STIX feed pricing and registration page inside VS Code. Browse tiers and sign up without leaving your editor.

### Improvements

- Updated publisher ID to `DugganUSALLC` to match VS Code Marketplace account
- Updated all marketplace links and install commands to use correct publisher ID
- Marketplace icon updated to 128x128 PNG

## 0.1.0 (2026-04-17)

### Initial Release

- Auto-scan on save and open for IPs, domains, SHA256 hashes, CVE IDs
- Right-click context menu: "DugganUSA: Look Up Selected Text"
- Workspace-wide scan command (up to 50 files)
- Cross-index correlation against 1.08M+ IOC database (44 indexes)
- 5-minute result cache to minimize API calls
- Smart false-positive filtering (skips localhost, DNS resolvers, common platform domains)
- First-run welcome with API key setup guidance and registration link
- Prerequisite checks on activation (API reachability, key format validation)
- Cross-platform: Windows, macOS, Linux, WSL, Remote SSH, GitHub Codespaces, vscode.dev
- Privacy-first: only IOC values transmitted, never source code or file paths
- MIT license, fully open source
