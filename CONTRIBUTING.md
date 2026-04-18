# Contributing to DugganUSA Threat Intel Scanner

Thanks for your interest in contributing. This extension is maintained by DugganUSA LLC.

## Getting Started

### Prerequisites

- [Node.js 18+](https://nodejs.org/)
- [VS Code 1.85+](https://code.visualstudio.com/)
- [vsce](https://github.com/microsoft/vscode-vsce) for packaging (`npm install -g @vscode/vsce`)

### Local Development

```bash
# Clone the repo
git clone https://github.com/pduggusa/dugganusa-vscode.git
cd dugganusa-vscode

# Open in VS Code
code .

# Press F5 to launch the Extension Development Host
# This opens a new VS Code window with the extension loaded
```

### Testing

1. Press F5 in VS Code to launch the Extension Development Host
2. Open any file containing IPs, domains, SHA256 hashes, or CVE IDs
3. Check the Problems panel for DugganUSA diagnostics
4. Right-click selected text and choose "DugganUSA: Look Up Selected Text"

### Building a VSIX Package

```bash
vsce package
# Produces dugganusa-threat-intel-0.1.0.vsix
```

### Publishing

Publishing requires a Personal Access Token from [Azure DevOps](https://dev.azure.com/).

```bash
vsce login dugganusa
vsce publish
```

## Guidelines

- Keep it cross-platform — no native dependencies, no shell calls, no OS-specific paths
- All API communication over HTTPS only
- Never transmit source code, file paths, or file contents to the API — IOC values only
- Cache API results (5-minute TTL) to minimize network calls
- Degrade gracefully when offline or when the API is unreachable

## Reporting Issues

Open an issue at [github.com/pduggusa/dugganusa-vscode/issues](https://github.com/pduggusa/dugganusa-vscode/issues).

## License

MIT — see [LICENSE](LICENSE).
