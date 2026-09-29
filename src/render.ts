import { ChainAnalysis, ChainLink, Finding, isSelfSigned } from './chain';
import { describeCertificate } from './certificate';
import { X509Certificate } from 'node:crypto';

export interface PageContext {
  cspSource: string;
  scriptUri: string;
  nonce: string;
}

const STYLE = `
    body { color: var(--vscode-foreground); background: var(--vscode-editor-background); font-family: var(--vscode-font-family); margin: 0; padding: 2rem; }
    .page { max-width: 900px; margin: 0 auto; }
    .header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }
    h1 { font-size: 1.6rem; font-weight: 600; margin: 0; }
    h2 { font-size: 1.1rem; font-weight: 600; margin: 1.75rem 0 .75rem; }
    .source { color: var(--vscode-descriptionForeground); margin-top: .25rem; overflow-wrap: anywhere; }
    fluent-divider { margin-bottom: 1.25rem; }
    .card { background: var(--vscode-editorWidget-background, var(--vscode-editor-background)); border: 1px solid var(--vscode-panel-border); border-radius: 8px; overflow: hidden; margin-bottom: 1rem; }
    .card-header { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; padding: .85rem 1.25rem; border-bottom: 1px solid var(--vscode-panel-border); }
    .card-title { flex: 1 1 100%; overflow-wrap: anywhere; }
    dl { margin: 0; }
    .field { display: grid; grid-template-columns: minmax(11rem, 28%) minmax(0, 1fr); gap: 1.25rem; padding: .8rem 1.25rem; border-bottom: 1px solid var(--vscode-panel-border); }
    .field:last-child { border-bottom: 0; }
    dt { color: var(--vscode-descriptionForeground); }
    dd { margin: 0; min-width: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
    fluent-text { color: var(--vscode-foreground); }
    .findings { list-style: none; margin: 0; padding: 0; }
    .findings li { display: flex; gap: .75rem; align-items: flex-start; padding: .7rem 1.25rem; border-bottom: 1px solid var(--vscode-panel-border); }
    .findings li:last-child { border-bottom: 0; }
    .findings fluent-badge { flex: none; }
    .link-arrow { text-align: center; color: var(--vscode-descriptionForeground); margin: -.25rem 0 .75rem; }
    .note { color: var(--vscode-descriptionForeground); margin-top: 1rem; }
    @media (max-width: 560px) {
      body { padding: 1rem; }
      .field { grid-template-columns: 1fr; gap: .4rem; padding: .9rem 1rem; }
      .header { align-items: flex-start; }
    }`;

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]!);
}

function shell(page: PageContext, title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${page.cspSource} 'unsafe-inline'; script-src 'nonce-${page.nonce}' ${page.cspSource};">
  <title>${escapeHtml(title)}</title>
  <style>${STYLE}
  </style>
</head>
<body>
  <main class="page">${body}
  </main>
  <script nonce="${page.nonce}" src="${page.scriptUri}"></script>
</body>
</html>`;
}

function badge(text: string, color: string): string {
  return `<fluent-badge appearance="tint" color="${color}">${escapeHtml(text)}</fluent-badge>`;
}

const STATUS_BADGES = {
  valid: ['Trusted', 'success'],
  warning: ['Trusted with warnings', 'warning'],
  invalid: ['Not trusted', 'danger']
} as const;

const FINDING_BADGES: Record<Finding['level'], [string, string]> = {
  ok: ['OK', 'success'],
  warning: ['Warning', 'warning'],
  error: ['Error', 'danger']
};

function certificateRows(certificate: X509Certificate): string {
  const details = describeCertificate(certificate);
  const rows: Array<[string, string, boolean]> = [
    ['Subject', details.subject, false],
    ['Issuer', details.issuer, false],
    ['Valid from', details.validFrom, false],
    ['Valid to', details.validTo, false],
    ['Serial number', details.serialNumber, true],
    ['SHA-256 fingerprint', details.fingerprint, true],
    ['Subject alternative names', details.subjectAlternativeNames, false],
    ['Public key type', details.publicKeyType, false],
    ['Certificate authority', details.isCa ? 'Yes' : 'No', false]
  ];
  return rows.map(([label, value, monospace]) =>
    `<div class="field"><dt><fluent-text size="200" weight="semibold">${escapeHtml(label)}</fluent-text></dt><dd><fluent-text block${monospace ? ' font="monospace"' : ''}>${escapeHtml(value)}</fluent-text></dd></div>`
  ).join('');
}

function certificateCard(certificate: X509Certificate, badges: string[]): string {
  return `
    <section class="card" aria-label="X.509 certificate properties">
      <div class="card-header">
        <div class="card-title"><fluent-text weight="semibold">${escapeHtml(certificate.subject || 'Not provided')}</fluent-text></div>
        ${badges.join('')}
      </div>
      <dl>${certificateRows(certificate)}</dl>
    </section>`;
}

function chainCard(link: ChainLink, index: number, analysis: ChainAnalysis): string {
  const role = isSelfSigned(link.certificate) ? 'Root CA' : index === 0 ? 'Leaf' : 'Intermediate CA';
  const badges = [
    badge(role, 'brand'),
    badge(link.origin === 'provided' ? 'Provided' : 'From trust store', 'informative')
  ];
  if (index === analysis.anchorIndex) {
    badges.push(badge('Trusted anchor', 'success'));
  }
  return certificateCard(link.certificate, badges);
}

export function renderCertificatePage(page: PageContext, sourceName: string, analysis: ChainAnalysis): string {
  const [statusText, statusColor] = STATUS_BADGES[analysis.status];
  const findings = analysis.findings.map(finding => {
    const [text, color] = FINDING_BADGES[finding.level];
    return `<li>${badge(text, color)}<fluent-text>${escapeHtml(finding.message)}</fluent-text></li>`;
  }).join('');
  const chain = analysis.chain.map((link, index) =>
    chainCard(link, index, analysis) + (index < analysis.chain.length - 1
      ? '<div class="link-arrow"><fluent-text size="200">issued by</fluent-text></div>'
      : '')
  ).join('');
  const others = analysis.others.length > 0
    ? `<h2><fluent-text size="500" weight="semibold">Other certificates in this file</fluent-text></h2>${
      analysis.others.map(certificate => certificateCard(certificate, [badge('Not part of the chain', 'subtle')])).join('')}`
    : '';

  return shell(page, 'Certificate details', `
    <header class="header">
      <div>
        <h1><fluent-text size="700" weight="semibold">Certificate details</fluent-text></h1>
        <div class="source"><fluent-text size="200">${escapeHtml(sourceName)}</fluent-text></div>
      </div>
      ${badge(statusText, statusColor)}
    </header>
    <fluent-divider></fluent-divider>
    <h2><fluent-text size="500" weight="semibold">Validation</fluent-text></h2>
    <section class="card" aria-label="Chain validation">
      <ul class="findings">${findings}</ul>
    </section>
    <h2><fluent-text size="500" weight="semibold">Certificate chain</fluent-text></h2>${chain}${others}
    <div class="note"><fluent-text size="200">Validation checks signatures, validity dates, CA constraints and the ${escapeHtml(analysis.trustSource)}. Revocation status and host names are not checked.</fluent-text></div>`);
}

export function renderMessagePage(page: PageContext, title: string, message: string): string {
  return shell(page, title, `
    <header class="header"><h1><fluent-text size="700" weight="semibold">${escapeHtml(title)}</fluent-text></h1></header>
    <fluent-divider></fluent-divider>
    <p><fluent-text>${escapeHtml(message)}</fluent-text></p>`);
}
