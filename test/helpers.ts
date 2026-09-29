import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import * as forge from 'node-forge';

export interface Issued {
  certificate: X509Certificate;
  pem: string;
  forgeCertificate: forge.pki.Certificate;
  privateKey: forge.pki.rsa.PrivateKey;
}

export interface IssueOptions {
  commonName: string;
  issuer?: Issued;
  ca?: boolean;
  notBefore?: Date;
  notAfter?: Date;
}

export function issue(options: IssueOptions): Issued {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const forgePublicKey = forge.pki.publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' }).toString());
  const forgePrivateKey = forge.pki.privateKeyFromPem(privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()) as forge.pki.rsa.PrivateKey;

  const certificate = forge.pki.createCertificate();
  certificate.publicKey = forgePublicKey;
  certificate.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(8));
  certificate.validity.notBefore = options.notBefore ?? new Date(Date.now() - 24 * 60 * 60 * 1000);
  certificate.validity.notAfter = options.notAfter ?? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  certificate.setSubject([{ name: 'commonName', value: options.commonName }]);
  certificate.setIssuer(options.issuer
    ? options.issuer.forgeCertificate.subject.attributes
    : [{ name: 'commonName', value: options.commonName }]);
  certificate.setExtensions([
    { name: 'basicConstraints', cA: options.ca ?? false },
    { name: 'subjectKeyIdentifier' }
  ]);
  certificate.sign(options.issuer?.privateKey ?? forgePrivateKey, forge.md.sha256.create());

  const pem = forge.pki.certificateToPem(certificate);
  return { certificate: new X509Certificate(pem), pem, forgeCertificate: certificate, privateKey: forgePrivateKey };
}

export function toPfx(leaf: Issued, chain: Issued[], password: string | null): Buffer {
  const asn1 = forge.pkcs12.toPkcs12Asn1(
    leaf.privateKey,
    [leaf, ...chain].map(item => item.forgeCertificate),
    password,
    { algorithm: '3des' }
  );
  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
}