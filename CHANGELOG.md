# Changelog

## 0.5.1 (2026-06-30)

### Added

- Documented the fourth live validation axis — Liveness ([/api/v1/feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy)) — alongside novelty, timeliness, and accuracy.

### Changed

- Refreshed IOC corpus copy to 1.5M+ IOCs (~1.57M live) and ~38M documents across 65 indexes.
- Reworded the Timeliness validation bullet to point at the live kev-lead ledger instead of a fixed "~31 days ahead" average.

## 0.5.0 (2026-06-27)

### Documentation & Feed-Awareness

- **Feed-quality validation, now provable live.** README now surfaces the three live, no-auth, durable validation endpoints behind the corpus your editor queries: novelty ([feed-uniqueness](https://analytics.dugganusa.com/api/v1/feed-uniqueness), ~75%+ not in ThreatFox), timeliness ([kev-lead](https://analytics.dugganusa.com/api/v1/kev-lead), ~31 days ahead of CISA KEV), and accuracy ([spamhaus-validation](https://analytics.dugganusa.com/api/v1/spamhaus-validation), independently corroborated).
- **API-key enforcement corrected.** The STIX feed is now API-key-enforced (anonymous → 401, unregistered Bearer → 429). Docs no longer imply the extension works without a key; the free tier is a free *registered* key. Register at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register).
- **IOC count aligned to 1.10M+** across README and changelog.
- **CLI reference fixed** — `npx dugganusa-cli` (the `dugganusa-lookup` package is retired).

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
- Cross-index correlation against 1.10M+ IOC database (44 indexes)
- 5-minute result cache to minimize API calls
- Smart false-positive filtering (skips localhost, DNS resolvers, common platform domains)
- First-run welcome with API key setup guidance and registration link
- Prerequisite checks on activation (API reachability, key format validation)
- Cross-platform: Windows, macOS, Linux, WSL, Remote SSH, GitHub Codespaces, vscode.dev
- Privacy-first: only IOC values transmitted, never source code or file paths
- MIT license, fully open source
