import assert from 'node:assert/strict';
import test from 'node:test';
import { describeCertificate, parseTlsSecretCertificates } from '../src/certificate';

const parseTlsSecretCertificate = (source: string) => {
  const certificates = parseTlsSecretCertificates(source);
  return certificates && describeCertificate(certificates[0]);
};

const secret = (fields: string) => `apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\n${fields}`;
const certificatePem = `-----BEGIN CERTIFICATE-----
MIICrjCCAZagAwIBAgIIXP8WgXGHolswDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UE
AxMMZXhhbXBsZS50ZXN0MB4XDTI2MDkyNzEwMTM0NVoXDTI2MTAyODEwMTM0NVow
FzEVMBMGA1UEAxMMZXhhbXBsZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAt3lyjn+g8nvrn0qtyrl5FZzPHc2ZzFJKnmg8BlU7z8s6mMj/1fuW
V2DBYQjRXeY7BudJzWS3SDVTf1pqufCvH/sy7oigCDNmbGLlONYrJKOkTmHvPWm7
r00ikCIguOwkYWoTxEixfHyBzMFfnRm8lzn11UPevddgbsBaXx8OdgfhHgWSfXF4
mv5X3geOuRLezz7kvlRUe2IjY4j7fjd5jfV6C1h8XbcDwL0PNcuV5H0yYWl6NemI
RT3DhYavJ4OWnnp/a2oFSsihWPrwuni8ECL0wfn+NuHLuMido2xYlpMZPvdiJ0Wh
9fLdNZ+hg4LyUHHjpCgNCHfcDkkw8ngwvQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQCN9buHEbdYvGahJcEIk4fS/7sEXcn78E1mCYXNjabum+kl1ZhU/QMn6Z2jToFn
uO/Uv/ovBZMpHh1B1XPiQj0uGs3YWNho4ZkC5m2QpsflJME7gRgJHsJm6IpU8N6w
B4c9tMHCtNsU28cByghGD+XSaJ+INbvNfXHMh/uUn8O2ecOnlZkTPgs4VOETvnOk
kRHrReQH57u10mJLiLhdvgiy7CbbRyTWYcZEbZPOMf0seO3OEzNXfQhEwWFbLXka
NAKCLcJ20mbYsbl+i0JnIU4zOTs+C9sr6ASxsn6QeuQs5yJxdbe1P8Rc0Osu75bP
3jbC4qdO5U3z7jtzfU2aGeSE
-----END CERTIFICATE-----`;

test('ignores YAML documents that are not Kubernetes TLS Secrets', () => {
  assert.equal(parseTlsSecretCertificate('kind: ConfigMap\ndata: {}'), undefined);
  assert.equal(parseTlsSecretCertificate('kind: Secret\ntype: Opaque\ndata: {}'), undefined);
});

test('parses a base64-encoded X.509 certificate from a TLS Secret', () => {
  const encoded = Buffer.from(certificatePem).toString('base64');
  const details = parseTlsSecretCertificate(secret(`data:\n  tls.crt: ${encoded}`));

  assert.equal(details?.subject, 'CN=example.test');
  assert.equal(details?.issuer, 'CN=example.test');
  assert.equal(details?.publicKeyType, 'rsa');
  assert.equal(details?.isCa, false);
  assert.equal(details?.subjectAlternativeNames, 'Not provided');
  assert.match(details?.fingerprint ?? '', /^[A-F0-9:]+$/);
});

test('parses a PEM certificate from stringData', () => {
  const pemLines = certificatePem.split('\n').map(line => `    ${line}`).join('\n');
  const details = parseTlsSecretCertificate(secret(`stringData:\n  tls.crt: |\n${pemLines}`));
  assert.equal(details?.subject, 'CN=example.test');
});

test('reports a TLS Secret without tls.crt', () => {
  assert.throws(() => parseTlsSecretCertificate(secret('data: {}')), /does not contain tls\.crt/);
});

test('rejects malformed base64 certificate data', () => {
  assert.throws(
    () => parseTlsSecretCertificate(secret('data:\n  tls.crt: "not base64!"')),
    /not valid base64/
  );
});

test('rejects certificate data that is not a valid X.509 certificate', () => {
  const encoded = Buffer.from('not a certificate').toString('base64');
  assert.throws(
    () => parseTlsSecretCertificate(secret(`data:\n  tls.crt: ${encoded}`)),
    /not a valid X\.509 certificate/
  );
});

test('rejects invalid YAML', () => {
  assert.throws(() => parseTlsSecretCertificate('kind: [Secret'), /Unable to parse YAML/);
});

test('returns every certificate in a tls.crt chain', () => {
  const encoded = Buffer.from(`${certificatePem}\n${certificatePem}`).toString('base64');
  const certificates = parseTlsSecretCertificates(secret(`data:\n  tls.crt: ${encoded}`));
  assert.equal(certificates?.length, 2);
});