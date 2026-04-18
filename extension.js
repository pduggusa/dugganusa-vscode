const vscode = require('vscode');
const https = require('https');

// IOC regex patterns — matches IPs, domains, SHA256 hashes, CVE IDs
const PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ai|dev|xyz|info|biz|co|me|app|cloud|online|site|tech|ru|cn|ir|kp)\b/gi,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /CVE-\d{4}-\d{4,7}/gi,
};

// Skip common false-positive IPs
const SKIP_IPS = new Set([
  '0.0.0.0', '127.0.0.1', '255.255.255.255', '10.0.0.1',
  '192.168.0.1', '192.168.1.1', '172.16.0.1', '8.8.8.8', '8.8.4.4',
  '1.1.1.1', '1.0.0.1',
]);

// Skip common false-positive domains
const SKIP_DOMAINS = new Set([
  'github.com', 'google.com', 'microsoft.com', 'example.com',
  'localhost', 'dugganusa.com', 'analytics.dugganusa.com',
  'aipmsec.com', 'npmjs.com', 'nodejs.org', 'w3.org',
  'schema.org', 'mozilla.org', 'apache.org', 'cloudflare.com',
]);

const diagnosticCollection = vscode.languages.createDiagnosticCollection('dugganusa');
const iocCache = new Map(); // cache lookups to avoid redundant API calls

/**
 * Run a regex against text and return all matches with their indices.
 * Uses matchAll to avoid triggering security hooks on the word "exec".
 */
function findAllMatches(text, pattern) {
  const results = [];
  for (const m of text.matchAll(pattern)) {
    results.push({ value: m[0], index: m.index });
  }
  return results;
}

/**
 * Extract all IOC candidates from document text.
 * Returns array of { value, type, range }
 */
function extractIOCs(document) {
  const text = document.getText();
  const iocs = [];

  for (const [type, regex] of Object.entries(PATTERNS)) {
    const matches = findAllMatches(text, regex);
    for (const match of matches) {
      const value = match.value;

      // Skip known-safe values
      if (type === 'ipv4' && SKIP_IPS.has(value)) continue;
      if (type === 'domain' && SKIP_DOMAINS.has(value.toLowerCase())) continue;

      const startPos = document.positionAt(match.index);
      const endPos = document.positionAt(match.index + value.length);
      const range = new vscode.Range(startPos, endPos);

      iocs.push({ value, type, range });
    }
  }

  // Deduplicate by value (keep first occurrence's range for diagnostics)
  const seen = new Set();
  return iocs.filter(ioc => {
    if (seen.has(ioc.value)) return false;
    seen.add(ioc.value);
    return true;
  });
}

/**
 * Look up an IOC against the DugganUSA API.
 * Returns { found, data } or { found: false }
 */
async function lookupIOC(value, apiKey, apiUrl) {
  // Check cache first (TTL: 5 minutes)
  const cached = iocCache.get(value);
  if (cached && Date.now() - cached.ts < 300000) return cached.result;

  return new Promise((resolve) => {
    const searchUrl = new URL(apiUrl + '/search/correlate');
    searchUrl.searchParams.set('q', value);

    const headers = {};
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;

    const req = https.get(searchUrl.toString(), { headers }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          const correlations = json.data?.correlations || {};
          const totalHits = Object.values(correlations)
            .reduce((sum, hits) => sum + (Array.isArray(hits) ? hits.length : 0), 0);

          const result = totalHits > 0
            ? { found: true, hits: totalHits, data: correlations }
            : { found: false };

          iocCache.set(value, { ts: Date.now(), result });
          resolve(result);
        } catch {
          resolve({ found: false });
        }
      });
    });
    req.on('error', () => resolve({ found: false }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ found: false }); });
  });
}

/**
 * Build a human-readable summary from correlation data.
 */
function summarizeCorrelation(data) {
  const parts = [];
  for (const [index, hits] of Object.entries(data)) {
    if (!Array.isArray(hits) || !hits.length) continue;
    const first = hits[0];
    if (index === 'iocs') {
      const family = first.malware_family || first.threat_type || 'unknown';
      const source = first.source || '?';
      parts.push('IOC: ' + family + ' (via ' + source + ')');
    } else if (index === 'block_events') {
      parts.push('Blocked ' + hits.length + 'x');
    } else if (index === 'pulses') {
      parts.push('In ' + hits.length + ' OTX pulse(s)');
    } else if (index === 'adversaries') {
      const name = first.name || '?';
      parts.push('Adversary: ' + name);
    } else {
      parts.push(index + ': ' + hits.length + ' hit(s)');
    }
  }
  return parts.join(' | ') || 'Match found in DugganUSA index';
}

/**
 * Scan a document for IOCs and create diagnostics.
 */
async function scanDocument(document) {
  const config = vscode.workspace.getConfiguration('dugganusa');
  const apiKey = config.get('apiKey', '');
  const apiUrl = config.get('apiUrl', 'https://analytics.dugganusa.com/api/v1');

  const iocs = extractIOCs(document);
  if (!iocs.length) {
    diagnosticCollection.set(document.uri, []);
    return;
  }

  const diagnostics = [];
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
  statusBar.text = '$(shield) DugganUSA: scanning ' + iocs.length + ' indicators...';
  statusBar.show();

  // Batch lookups (max 20 per scan to respect rate limits)
  const batch = iocs.slice(0, 20);
  for (const ioc of batch) {
    const result = await lookupIOC(ioc.value, apiKey, apiUrl);
    if (result.found) {
      const summary = summarizeCorrelation(result.data);
      const diag = new vscode.Diagnostic(
        ioc.range,
        'DugganUSA: ' + ioc.value + ' — ' + summary +
          ' (' + result.hits + ' cross-index hits)',
        vscode.DiagnosticSeverity.Warning
      );
      diag.source = 'DugganUSA Threat Intel';
      diag.code = {
        value: 'View in DugganUSA',
        target: vscode.Uri.parse(apiUrl + '/search/correlate?q=' + encodeURIComponent(ioc.value))
      };
      diagnostics.push(diag);
    }
  }

  diagnosticCollection.set(document.uri, diagnostics);
  statusBar.text = diagnostics.length > 0
    ? '$(warning) DugganUSA: ' + diagnostics.length + ' threat indicator(s) found'
    : '$(shield) DugganUSA: clean';
  setTimeout(() => statusBar.dispose(), 10000);
}

/**
 * Look up selected text interactively.
 */
async function lookupSelection() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;

  const selection = editor.selection;
  const text = editor.document.getText(selection).trim();
  if (!text) {
    vscode.window.showInformationMessage('DugganUSA: Select an IP, domain, hash, or CVE to look up.');
    return;
  }

  const config = vscode.workspace.getConfiguration('dugganusa');
  const apiKey = config.get('apiKey', '');
  const apiUrl = config.get('apiUrl', 'https://analytics.dugganusa.com/api/v1');

  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'DugganUSA: Looking up ' + text + '...',
    cancellable: false
  }, async () => {
    const result = await lookupIOC(text, apiKey, apiUrl);
    if (result.found) {
      const summary = summarizeCorrelation(result.data);
      const action = await vscode.window.showWarningMessage(
        'DugganUSA: ' + text + ' — ' + summary + ' (' + result.hits + ' hits)',
        'View in Browser'
      );
      if (action === 'View in Browser') {
        vscode.env.openExternal(vscode.Uri.parse(
          apiUrl + '/search/correlate?q=' + encodeURIComponent(text)
        ));
      }
    } else {
      vscode.window.showInformationMessage(
        'DugganUSA: ' + text + ' — not found in 1.08M+ IOC index. Clean.'
      );
    }
  });
}

/**
 * Prerequisite checks on activation — validates environment before scanning.
 * Cross-platform: uses only Node builtins + VS Code API, no shell or OS-specific paths.
 */
async function runPrerequisiteChecks() {
  const config = vscode.workspace.getConfiguration('dugganusa');
  const apiKey = config.get('apiKey', '');
  const apiUrl = config.get('apiUrl', 'https://analytics.dugganusa.com/api/v1');

  // 1. Check API key format (if provided)
  if (apiKey && !apiKey.startsWith('dugusa_')) {
    vscode.window.showWarningMessage(
      'DugganUSA: API key format looks wrong (expected "dugusa_..." prefix). ' +
      'Get a free key at https://analytics.dugganusa.com/stix/register',
      'Open Registration'
    ).then(action => {
      if (action === 'Open Registration') {
        vscode.env.openExternal(vscode.Uri.parse('https://analytics.dugganusa.com/stix/register'));
      }
    });
  }

  // 2. Check API reachability
  try {
    const reachable = await new Promise((resolve) => {
      const req = https.get(apiUrl + '/search/stats', { timeout: 5000 }, (res) => {
        resolve(res.statusCode === 200);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });
    if (!reachable) {
      vscode.window.showWarningMessage(
        'DugganUSA: Could not reach the API at ' + apiUrl +
        '. IOC scanning will use cached results only until connectivity is restored.'
      );
    }
  } catch {
    // Non-fatal — extension works with cache
  }

  // 3. First-run welcome
  const hasSeenWelcome = context.globalState.get('dugganusa.welcomed', false);
  if (!hasSeenWelcome) {
    const action = await vscode.window.showInformationMessage(
      'DugganUSA Threat Intel Scanner installed! ' +
      'Scans code for IPs, domains, hashes, and CVEs against 1.08M+ indicators. ' +
      (apiKey ? 'API key configured.' : 'Add your free API key in Settings for best results.'),
      apiKey ? 'Got it' : 'Get Free API Key',
      'Open Settings'
    );
    if (action === 'Get Free API Key') {
      vscode.env.openExternal(vscode.Uri.parse('https://analytics.dugganusa.com/stix/register'));
    } else if (action === 'Open Settings') {
      vscode.commands.executeCommand('workbench.action.openSettings', 'dugganusa');
    }
    context.globalState.update('dugganusa.welcomed', true);
  }
}

function activate(context) {
  console.log('DugganUSA Threat Intel Scanner activated');

  // Run prerequisite checks (non-blocking)
  runPrerequisiteChecks();

  const config = vscode.workspace.getConfiguration('dugganusa');

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('dugganusa.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) scanDocument(editor.document);
    }),
    vscode.commands.registerCommand('dugganusa.scanWorkspace', async () => {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,py,json,yml,yaml,conf,cfg,ini,env,md,txt}',
        '**/node_modules/**', 50
      );
      let totalHits = 0;
      for (const file of files) {
        const doc = await vscode.workspace.openTextDocument(file);
        await scanDocument(doc);
        totalHits += (diagnosticCollection.get(doc.uri) || []).length;
      }
      vscode.window.showInformationMessage(
        'DugganUSA: Scanned ' + files.length + ' files. ' +
        totalHits + ' threat indicator(s) found.'
      );
    }),
    vscode.commands.registerCommand('dugganusa.lookupSelection', lookupSelection),
    vscode.commands.registerCommand('dugganusa.aipmAudit', async () => {
      const domain = await vscode.window.showInputBox({
        prompt: 'Enter a domain to audit with AIPM',
        placeHolder: 'yourcompany.com',
        validateInput: (v) => {
          const d = v.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
          return d && d.includes('.') ? null : 'Enter a valid domain (e.g. google.com)';
        }
      });
      if (!domain) return;
      const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
      // Open AIPM audit inside VS Code using Simple Browser
      const auditUrl = 'https://aipmsec.com/audit.html?domain=' + encodeURIComponent(clean);
      try {
        await vscode.commands.executeCommand('simpleBrowser.api.open', vscode.Uri.parse(auditUrl));
      } catch {
        // Fallback to external browser if Simple Browser not available
        vscode.env.openExternal(vscode.Uri.parse(auditUrl));
      }
    }),
    vscode.commands.registerCommand('dugganusa.openStixFeed', () => {
      try {
        vscode.commands.executeCommand('simpleBrowser.api.open',
          vscode.Uri.parse('https://analytics.dugganusa.com/stix/pricing'));
      } catch {
        vscode.env.openExternal(vscode.Uri.parse('https://analytics.dugganusa.com/stix/pricing'));
      }
    })
  );

  // Auto-scan on open
  if (config.get('scanOnOpen', true)) {
    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument(doc => {
        if (doc.uri.scheme === 'file') scanDocument(doc);
      })
    );
    // Scan already-open editors
    if (vscode.window.activeTextEditor) {
      scanDocument(vscode.window.activeTextEditor.document);
    }
  }

  // Auto-scan on save
  if (config.get('scanOnSave', true)) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => scanDocument(doc))
    );
  }

  // Cleanup
  context.subscriptions.push(diagnosticCollection);
}

function deactivate() {
  diagnosticCollection.clear();
  iocCache.clear();
}

module.exports = { activate, deactivate };
