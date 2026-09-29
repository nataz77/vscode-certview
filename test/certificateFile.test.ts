import assert from 'node:assert/strict';
import test from 'node:test';
import { PfxPasswordError, parseCertificateFile } from '../src/certificateFile';
import { issue, toPfx } from './helpers';

const root = issue({ commonName: 'Test Root', ca: true });
const leaf = issue({ commonName: 'leaf.test', issuer: root });
const subjects = (certificates: Array<{ subject: string }>) => certificates.map(certificate => certificate.subject);

test('parses a PEM file containing several certificates and a private key', () => {
  const data = Buffer.from(`-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n${leaf.pem}\n${root.pem}`);
  assert.deepEqual(subjects(parseCertificateFile(data)), ['CN=leaf.test', 'CN=Test Root']);
});

test('parses a DER encoded certificate', () => {
  const data = Buffer.from(leaf.certificate.raw);
  assert.deepEqual(subjects(parseCertificateFile(data)), ['CN=leaf.test']);
});

test('parses a password protected PFX file', () => {
  const data = toPfx(leaf, [root], 'secret');
  assert.deepEqual(subjects(parseCertificateFile(data, 'secret')), ['CN=leaf.test', 'CN=Test Root']);
});

test('parses a PFX file without a password', () => {
  const data = toPfx(leaf, [root], null);
  assert.deepEqual(subjects(parseCertificateFile(data)), ['CN=leaf.test', 'CN=Test Root']);
});

test('requests a password for a protected PFX file', () => {
  const data = toPfx(leaf, [], 'secret');
  assert.throws(() => parseCertificateFile(data), (error: unknown) => error instanceof PfxPasswordError && !error.passwordProvided);
});

test('rejects a wrong PFX password', () => {
  const data = toPfx(leaf, [], 'secret');
  assert.throws(() => parseCertificateFile(data, 'wrong'), (error: unknown) => error instanceof PfxPasswordError && error.passwordProvided);
});

test('rejects a PEM file that only contains a private key', () => {
  const data = Buffer.from('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n');
  assert.throws(() => parseCertificateFile(data), /private key but no certificate/);
});

test('rejects files that are not certificates', () => {
  assert.throws(() => parseCertificateFile(Buffer.from('hello')), /not a valid certificate/);
});