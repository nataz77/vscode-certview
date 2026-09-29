import { X509Certificate } from 'node:crypto';
import { parseAllDocuments } from 'yaml';

export interface CertificateDetails {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  subjectAlternativeNames: string;
  publicKeyType: string;
  isCa: boolean;
}

export class TlsSecretError extends Error {}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function splitPemCertificates(text: string): string[] {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

export function parsePemCertificates(text: string): X509Certificate[] {
  return splitPemCertificates(text).map(pem => new X509Certificate(pem));
}

function decodeCertificate(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
    return trimmed;
  }

  const encoded = trimmed.replace(/\s+/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new TlsSecretError('The Secret data.tls.crt value is not valid base64.');
  }

  return Buffer.from(encoded, 'base64').toString('utf8');
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toUTCString();
}

export function describeCertificate(certificate: X509Certificate): CertificateDetails {
  return {
    subject: certificate.subject || 'Not provided',
    issuer: certificate.issuer || 'Not provided',
    validFrom: formatDate(certificate.validFrom),
    validTo: formatDate(certificate.validTo),
    serialNumber: certificate.serialNumber || 'Not provided',
    fingerprint: certificate.fingerprint256 || 'Not provided',
    subjectAlternativeNames: certificate.subjectAltName || 'Not provided',
    publicKeyType: certificate.publicKey.asymmetricKeyType || 'Not provided',
    isCa: certificate.ca
  };
}

export function parseTlsSecretCertificates(source: string): X509Certificate[] | undefined {
  const documents = parseAllDocuments(source, { uniqueKeys: true });
  const parseErrors = documents.flatMap(document => document.errors);
  if (parseErrors.length > 0) {
    throw new Error(`Unable to parse YAML: ${parseErrors[0].message}`);
  }

  for (const document of documents) {
    const secret = asRecord(document.toJS());
    if (secret?.kind !== 'Secret' || secret.type !== 'kubernetes.io/tls') {
      continue;
    }

    const stringData = asRecord(secret.stringData);
    const data = asRecord(secret.data);
    const pem = decodeCertificate(stringData?.['tls.crt'] ?? data?.['tls.crt']);
    if (!pem) {
      throw new TlsSecretError('This TLS Secret does not contain tls.crt.');
    }

    try {
      const certificates = parsePemCertificates(pem);
      if (certificates.length === 0) {
        throw new Error('No certificate found.');
      }
      return certificates;
    } catch {
      throw new TlsSecretError('The Secret tls.crt value is not a valid X.509 certificate.');
    }
  }

  return undefined;
}