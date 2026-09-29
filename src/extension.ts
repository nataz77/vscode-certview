import { X509Certificate, randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import { TlsSecretError, parseTlsSecretCertificates } from './certificate';
import { PfxPasswordError, parseCertificateFile } from './certificateFile';
import { analyzeChain } from './chain';
import { PageContext, renderCertificatePage, renderMessagePage } from './render';
import { TrustStore, loadTrustStore } from './trust';

type Mode = 'command' | 'follow' | 'refresh';
type FileKind = 'yaml' | 'certificate';

const CERTIFICATE_EXTENSIONS = /\.(crt|cer|pem|pfx|p12)$/i;
const BINARY_EXTENSIONS = /\.(pfx|p12)$/i;
const YAML_EXTENSIONS = /\.ya?ml$/i;
const TRUST_STORE_TTL_MS = 5 * 60 * 1000;

let panel: vscode.WebviewPanel | undefined;
let currentUri: vscode.Uri | undefined;
let requestId = 0;
let trustCache: { store: TrustStore; loadedAt: number } | undefined;

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.window.tabGroups.onDidChangeTabs(() => followActiveEditor(context)),
    vscode.window.onDidChangeActiveTextEditor(() => followActiveEditor(context)),
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.contentChanges.length > 0 && currentUri && event.document.uri.toString() === currentUri.toString()) {
        void present(context, currentUri, 'refresh');
      }
    }),
    vscode.commands.registerCommand('certview.showCertificate', async (resource?: vscode.Uri) => {
      const uri = resource instanceof vscode.Uri
        ? resource
        : activeUri() ?? vscode.window.activeTextEditor?.document.uri;
      if (!uri || !fileKind(uri)) {
        await vscode.window.showInformationMessage('Open a Kubernetes TLS Secret YAML, or a .crt, .pem or .pfx file first.');
        return;
      }
      await present(context, uri, 'command');
    }),
    { dispose: () => panel?.dispose() }
  );
}

function fileKind(uri: vscode.Uri): FileKind | undefined {
  if (CERTIFICATE_EXTENSIONS.test(uri.path)) {
    return 'certificate';
  }
  if (YAML_EXTENSIONS.test(uri.path)) {
    return 'yaml';
  }
  const document = vscode.workspace.textDocuments.find(candidate => candidate.uri.toString() === uri.toString());
  return document?.languageId === 'yaml' ? 'yaml' : undefined;
}

function activeUri(): vscode.Uri | undefined {
  const input = vscode.window.tabGroups.activeTabGroup.activeTab?.input;
  return input instanceof vscode.TabInputText || input instanceof vscode.TabInputCustom ? input.uri : undefined;
}

function followActiveEditor(context: vscode.ExtensionContext): void {
  const uri = activeUri();
  if (!panel || !uri || uri.toString() === currentUri?.toString() || !fileKind(uri)) {
    return;
  }
  void present(context, uri, 'follow');
}

async function loadCertificates(uri: vscode.Uri, kind: FileKind, password?: string): Promise<X509Certificate[] | undefined> {
  const openDocument = vscode.workspace.textDocuments.find(document => document.uri.toString() === uri.toString());
  if (kind === 'yaml') {
    const document = openDocument ?? await vscode.workspace.openTextDocument(uri);
    return parseTlsSecretCertificates(document.getText());
  }

  if (openDocument && !BINARY_EXTENSIONS.test(uri.path)) {
    return parseCertificateFile(Buffer.from(openDocument.getText(), 'utf8'), password);
  }
  return parseCertificateFile(Buffer.from(await vscode.workspace.fs.readFile(uri)), password);
}

function trustStore(): TrustStore {
  if (!trustCache || Date.now() - trustCache.loadedAt > TRUST_STORE_TTL_MS) {
    trustCache = { store: loadTrustStore(), loadedAt: Date.now() };
  }
  return trustCache.store;
}

async function present(context: vscode.ExtensionContext, uri: vscode.Uri, mode: Mode): Promise<void> {
  const kind = fileKind(uri);
  if (!kind) {
    return;
  }

  const id = ++requestId;
  const name = uri.path.split('/').pop() ?? 'certificate';
  const display = (render: (page: PageContext) => string) => show(context, uri, name, mode === 'command', render);
  let password: string | undefined;

  for (;;) {
    try {
      const certificates = await loadCertificates(uri, kind, password);
      if (id !== requestId) {
        return;
      }
      if (!certificates || certificates.length === 0) {
        if (mode === 'command') {
          await vscode.window.showInformationMessage('The selected file is not a Kubernetes TLS Secret.');
        } else if (mode === 'refresh') {
          display(page => renderMessagePage(page, 'No certificate', 'This file no longer contains a Kubernetes TLS Secret certificate.'));
        }
        return;
      }

      const analysis = analyzeChain(certificates, trustStore());
      display(page => renderCertificatePage(page, name, analysis));
      return;
    } catch (error) {
      if (id !== requestId) {
        return;
      }

      if (error instanceof PfxPasswordError) {
        if (mode !== 'command') {
          display(page => renderMessagePage(page, 'Password required', 'This PKCS#12 file is password protected. Run "CertView: Show Certificate Details" to enter the password.'));
          return;
        }
        password = await vscode.window.showInputBox({
          title: `Password for ${name}`,
          prompt: error.passwordProvided ? 'Incorrect password. Try again.' : 'Enter the PKCS#12 password. It is used once and never stored.',
          password: true,
          ignoreFocusOut: true
        });
        if (password === undefined || id !== requestId) {
          return;
        }
        continue;
      }

      const message = errorMessage(error);
      if (mode === 'command') {
        await vscode.window.showErrorMessage(message);
      } else if (kind === 'certificate' || mode === 'refresh' || error instanceof TlsSecretError) {
        display(page => renderMessagePage(page, 'Certificate error', message));
      }
      return;
    }
  }
}

function show(
  context: vscode.ExtensionContext,
  uri: vscode.Uri,
  name: string,
  reveal: boolean,
  render: (page: PageContext) => string
): void {
  const title = `Certificate: ${name}`;
  if (!panel) {
    const created = vscode.window.createWebviewPanel(
      'certview.certificate',
      title,
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'out')]
      }
    );
    created.onDidDispose(() => {
      if (panel === created) {
        panel = undefined;
        currentUri = undefined;
      }
    });
    panel = created;
  } else if (reveal) {
    panel.reveal(panel.viewColumn, true);
  }

  currentUri = uri;
  panel.title = title;
  panel.webview.html = render({
    cspSource: panel.webview.cspSource,
    scriptUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'out', 'webview.js')).toString(),
    nonce: randomBytes(16).toString('base64')
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to read the certificate.';
}
