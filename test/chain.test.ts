import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeChain } from '../src/chain';
import { TrustStore } from '../src/trust';
import { issue } from './helpers';

const root = issue({ commonName: 'Test Root', ca: true });
const intermediate = issue({ commonName: 'Test Intermediate', ca: true, issuer: root });
const leaf = issue({ commonName: 'leaf.test', issuer: intermediate });
const trust: TrustStore = { certificates: [root.certificate], source: 'test store' };

test('builds and validates a full chain anchored in the trust store', () => {
  const analysis = analyzeChain([leaf.certificate, intermediate.certificate], trust);

  assert.deepEqual(analysis.chain.map(link => link.certificate.subject), ['CN=leaf.test', 'CN=Test Intermediate', 'CN=Test Root']);
  assert.deepEqual(analysis.chain.map(link => link.origin), ['provided', 'provided', 'trust-store']);
  assert.equal(analysis.anchorIndex, 2);
  assert.equal(analysis.status, 'valid');
});

test('finds the leaf regardless of the order of the provided certificates', () => {
  const analysis = analyzeChain([root.certificate, intermediate.certificate, leaf.certificate], trust);

  assert.equal(analysis.chain[0].certificate.subject, 'CN=leaf.test');
  assert.equal(analysis.chain[2].origin, 'provided');
  assert.equal(analysis.anchorIndex, 2);
  assert.equal(analysis.status, 'valid');
});

test('reports a chain whose root is not trusted', () => {
  const analysis = analyzeChain([leaf.certificate, intermediate.certificate, root.certificate], { certificates: [], source: 'empty store' });

  assert.equal(analysis.anchorIndex, -1);
  assert.equal(analysis.status, 'invalid');
  assert.match(analysis.findings.map(finding => finding.message).join('\n'), /not in the empty store/);
});

test('reports an incomplete chain when an intermediate is missing', () => {
  const analysis = analyzeChain([leaf.certificate], trust);

  assert.equal(analysis.chain.length, 1);
  assert.equal(analysis.status, 'invalid');
  assert.match(analysis.findings.map(finding => finding.message).join('\n'), /chain is incomplete/);
});

test('reports expired certificates', () => {
  const analysis = analyzeChain([leaf.certificate, intermediate.certificate], trust, new Date(Date.now() + 2 * 365 * 24 * 60 * 60 * 1000));

  assert.equal(analysis.status, 'invalid');
  assert.match(analysis.findings.map(finding => finding.message).join('\n'), /"CN=leaf\.test" expired/);
});

test('warns when the leaf is about to expire', () => {
  const expiring = issue({ commonName: 'soon.test', issuer: intermediate, notAfter: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000) });
  const analysis = analyzeChain([expiring.certificate, intermediate.certificate], trust);

  assert.equal(analysis.status, 'warning');
});

test('rejects an issuer that is not a CA', () => {
  const notCa = issue({ commonName: 'Not A CA', issuer: root });
  const child = issue({ commonName: 'child.test', issuer: notCa });
  const analysis = analyzeChain([child.certificate, notCa.certificate], trust);

  assert.equal(analysis.status, 'invalid');
  assert.match(analysis.findings.map(finding => finding.message).join('\n'), /not marked as a CA/);
});

test('lists certificates that are not part of the chain', () => {
  const stranger = issue({ commonName: 'Stranger', ca: true });
  const analysis = analyzeChain([leaf.certificate, intermediate.certificate, stranger.certificate], trust);

  assert.deepEqual(analysis.others.map(certificate => certificate.subject), ['CN=Stranger']);
});

test('does not loop on a self-signed leaf', () => {
  const analysis = analyzeChain([root.certificate], { certificates: [], source: 'empty store' });

  assert.equal(analysis.chain.length, 1);
  assert.equal(analysis.status, 'invalid');
});