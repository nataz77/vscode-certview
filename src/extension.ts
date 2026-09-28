import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import { CertificateDetails, parseTlsSecretCertificate } from './certificate';

const panels = new Map<string, vscode.WebviewPanel>();

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (panels.has(event.document.uri.toString())) {
        showCertificate(context, event.document, true);
      }
    }),
    vscode.commands.registerCommand('yamlcert.showCertificate', async () => {
      const document = vscode.window.activeTextEditor?.document;
      if (!document) {
        return;
      }

      try {
        const details = parseTlsSecretCertificate(document.getText());
        if (!details) {
          await vscode.window.showInformationMessage('The active file is not a Kubernetes TLS Secret.');
          return;
        }
        displayCertificate(context, document, details);
      } catch (error) {
        await vscode.window.showErrorMessage(errorMessage(error));
      }
    })
  );
}

function showCertificate(context: vscode.ExtensionContext, document: vscode.TextDocument, refreshing = false): void {
  if (document.languageId !== 'yaml') {
    return;
  }

  const key = document.uri.toString();
  try {
    const details = parseTlsSecretCertificate(document.getText());
    if (details) {
      displayCertificate(context, document, details, !refreshing);
    } else if (refreshing) {
      panels.get(key)?.dispose();
    }
  } catch (error) {
    const panel = panels.get(key);
    if (panel) {
      panel.webview.html = renderError(errorMessage(error));
    } else if (!refreshing && /type:\s*["']?kubernetes\.io\/tls/.test(document.getText())) {
      vscode.window.showErrorMessage(errorMessage(error));
    }
  }
}

function displayCertificate(context: vscode.ExtensionContext, document: vscode.TextDocument, details: CertificateDetails, reveal = true): void {
  const key = document.uri.toString();
  let panel = panels.get(key);
  if (panel) {
    if (reveal) {
      panel.reveal(vscode.ViewColumn.Beside);
    }
  } else {
    panel = vscode.window.createWebviewPanel(
      'yamlcert.certificate',
      `Certificate: ${document.fileName.split(/[\\/]/).pop() ?? 'TLS Secret'}`,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'out')]
      }
    );
    panels.set(key, panel);
    panel.onDidDispose(() => panels.delete(key));
  }
  panel.title = `Certificate: ${document.fileName.split(/[\\/]/).pop() ?? 'TLS Secret'}`;
  panel.webview.html = renderCertificate(context, panel.webview, details);
}

function renderCertificate(
  context: vscode.ExtensionContext,
  webview: vscode.Webview,
  details: CertificateDetails
): string {
  const rows: Array<[string, string, boolean]> = [
    ['Subject', details.subject, false],
    ['Issuer', details.issuer, false],
    ['Valid from', details.validFrom, false],
    ['Valid to', details.validTo, false],
    ['Serial number', details.serialNumber, true],
    ['SHA-256 fingerprint', details.fingerprint, true],
    ['Subject alternative names', details.subjectAlternativeNames, false],
    ['Public key type', details.publicKeyType, false]
  ];
  const rowsHtml = rows.map(([label, value, monospace]) =>
    `<div class="field"><dt><fluent-text size="200" weight="semibold">${escapeHtml(label)}</fluent-text></dt><dd><fluent-text block${monospace ? ' font="monospace"' : ''}>${escapeHtml(value)}</fluent-text></dd></div>`
  ).join('');
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'out', 'webview.js'));
  const nonce = randomBytes(16).toString('base64');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}' ${webview.cspSource};">
  <title>Certificate details</title>
  <style>
    body { color: var(--vscode-foreground); background: var(--vscode-editor-background); font-family: var(--vscode-font-family); margin: 0; padding: 2rem; }
    .page { max-width: 900px; margin: 0 auto; }
    .header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }
    .eyebrow { color: var(--vscode-descriptionForeground); letter-spacing: .08em; text-transform: uppercase; }
    h1 { font-size: 1.6rem; font-weight: 600; margin: .25rem 0 0; }
    fluent-divider { margin-bottom: 1.25rem; }
    .details { background: var(--vscode-editorWidget-background, var(--vscode-editor-background)); border: 1px solid var(--vscode-panel-border); border-radius: 8px; overflow: hidden; }
    dl { margin: 0; }
    .field { display: grid; grid-template-columns: minmax(11rem, 28%) minmax(0, 1fr); gap: 1.25rem; padding: 1rem 1.25rem; border-bottom: 1px solid var(--vscode-panel-border); }
    .field:last-child { border-bottom: 0; }
    dt { color: var(--vscode-descriptionForeground); }
    dd { margin: 0; min-width: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
    fluent-text { color: var(--vscode-foreground); }
    .eyebrow fluent-text { color: var(--vscode-descriptionForeground); }
    .note { color: var(--vscode-descriptionForeground); margin-top: 1rem; }
    @media (max-width: 560px) {
      body { padding: 1rem; }
      .field { grid-template-columns: 1fr; gap: .4rem; padding: .9rem 1rem; }
      .header { align-items: flex-start; }
    }
  </style>
</head>
<body>
  <main class="page">
    <header class="header">
      <div>
        <h1><fluent-text size="700" weight="semibold">Certificate details</fluent-text></h1>
      </div>
      <fluent-badge appearance="tint" color="informative">X.509</fluent-badge>
    </header>
    <fluent-divider></fluent-divider>
    <section class="details" aria-label="X.509 certificate properties">
      <dl>${rowsHtml}</dl>
    </section>
    <div class="note"><fluent-text size="200">Certificate details are parsed locally; trust and chain validation are not performed.</fluent-text></div>
  </main>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none';">
  <title>Certificate error</title>
</head>
<body><p>${escapeHtml(message)}</p></body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]!);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to read the TLS certificate.';
}
