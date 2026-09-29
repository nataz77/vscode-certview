import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeChain } from '../src/chain';
import { renderCertificatePage, renderMessagePage } from '../src/render';
import { issue } from './helpers';

const page = { cspSource: 'vscode-resource:', scriptUri: 'vscode-resource:/webview.js', nonce: 'abc' };

test('renders validation status, chain roles and origins', () => {
  const root = issue({ commonName: 'Test Root', ca: true });
  const leaf = issue({ commonName: 'leaf.test', issuer: root });
  const html = renderCertificatePage(page, 'leaf.pem', analyzeChain([leaf.certificate], { certificates: [root.certificate], source: 'test store' }));

  assert.match(html, /Trusted</);
  assert.match(html, /Leaf</);
  assert.match(html, /Root CA</);
  assert.match(html, /From trust store</);
  assert.match(html, /Trusted anchor</);
});

test('escapes HTML in messages', () => {
  const html = renderMessagePage(page, 'Error', '<script>alert(1)</script>');
  assert.ok(!html.includes('<script>alert(1)'));
  assert.match(html, /&lt;script&gt;/);
});