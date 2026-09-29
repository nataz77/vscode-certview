import { X509Certificate } from 'node:crypto';
import * as tls from 'node:tls';

export interface TrustStore {
  certificates: X509Certificate[];
  source: string;
}

type GetCaCertificates = (type: 'system' | 'extra') => string[];

function parseAll(pems: readonly string[]): X509Certificate[] {
  const certificates: X509Certificate[] = [];
  for (const pem of pems) {
    try {
      certificates.push(new X509Certificate(pem));
    } catch {
      continue;
    }
  }
  return certificates;
}

export function loadTrustStore(): TrustStore {
  const getCaCertificates = (tls as unknown as { getCACertificates?: GetCaCertificates }).getCACertificates;
  if (typeof getCaCertificates === 'function') {
    try {
      const certificates = parseAll([...getCaCertificates('system'), ...getCaCertificates('extra')]);
      if (certificates.length > 0) {
        return { certificates, source: 'operating system trust store' };
      }
    } catch {
      // Fall back to the bundled roots below.
    }
  }

  return {
    certificates: parseAll(tls.rootCertificates),
    source: 'bundled Mozilla root certificates (the operating system store is not accessible from this runtime)'
  };
}