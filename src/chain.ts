import { X509Certificate } from 'node:crypto';
import { TrustStore } from './trust';

export type ChainOrigin = 'provided' | 'trust-store';

export interface ChainLink {
  certificate: X509Certificate;
  origin: ChainOrigin;
}

export interface Finding {
  level: 'ok' | 'warning' | 'error';
  message: string;
}

export interface ChainAnalysis {
  chain: ChainLink[];
  others: X509Certificate[];
  anchorIndex: number;
  status: 'valid' | 'warning' | 'invalid';
  trustSource: string;
  findings: Finding[];
}

const EXPIRY_WARNING_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

function name(value: string): string {
  return value.replace(/\r?\n/g, ', ');
}

function isIssuedBy(certificate: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

export function isSelfSigned(certificate: X509Certificate): boolean {
  return isIssuedBy(certificate, certificate);
}

function isCurrentlyValid(certificate: X509Certificate, now: Date): boolean {
  return new Date(certificate.validFrom) <= now && now <= new Date(certificate.validTo);
}

function unique(certificates: X509Certificate[]): X509Certificate[] {
  const seen = new Set<string>();
  return certificates.filter(certificate => {
    if (seen.has(certificate.fingerprint256)) {
      return false;
    }
    seen.add(certificate.fingerprint256);
    return true;
  });
}

function findIssuer(certificate: X509Certificate, candidates: X509Certificate[], now: Date): X509Certificate | undefined {
  const issuers = candidates.filter(candidate =>
    candidate.fingerprint256 !== certificate.fingerprint256 && isIssuedBy(certificate, candidate));
  return issuers.find(issuer => isCurrentlyValid(issuer, now)) ?? issuers[0];
}

function selectLeaf(certificates: X509Certificate[]): X509Certificate {
  const leaf = certificates.find(certificate =>
    !certificates.some(other => other !== certificate && isIssuedBy(other, certificate) && !isSelfSigned(other)));
  return leaf ?? certificates[0];
}

export function analyzeChain(certificates: X509Certificate[], trust: TrustStore, now = new Date()): ChainAnalysis {
  const provided = unique(certificates);
  const trusted = new Set(trust.certificates.map(certificate => certificate.fingerprint256));
  const findings: Finding[] = [];

  const chain: ChainLink[] = [{ certificate: selectLeaf(provided), origin: 'provided' }];
  const seen = new Set([chain[0].certificate.fingerprint256]);
  for (;;) {
    const current = chain[chain.length - 1].certificate;
    if (isSelfSigned(current)) {
      break;
    }
    const fromProvided = findIssuer(current, provided, now);
    const issuer = fromProvided ?? findIssuer(current, trust.certificates, now);
    if (!issuer || seen.has(issuer.fingerprint256)) {
      break;
    }
    seen.add(issuer.fingerprint256);
    chain.push({ certificate: issuer, origin: fromProvided ? 'provided' : 'trust-store' });
  }

  const others = provided.filter(certificate => !seen.has(certificate.fingerprint256));
  const anchorIndex = chain.findIndex(link => trusted.has(link.certificate.fingerprint256));
  const verified = chain.slice(0, anchorIndex >= 0 ? anchorIndex + 1 : chain.length);
  const last = chain[chain.length - 1].certificate;

  if (anchorIndex >= 0) {
    findings.push({
      level: 'ok',
      message: `Chain is anchored at "${name(chain[anchorIndex].certificate.subject)}", trusted by the ${trust.source}.`
    });
  } else if (isSelfSigned(last)) {
    findings.push({ level: 'error', message: `The root "${name(last.subject)}" is not in the ${trust.source}.` });
  } else {
    findings.push({
      level: 'error',
      message: `The issuer "${name(last.issuer)}" was not found in the provided certificates or the ${trust.source}; the chain is incomplete.`
    });
  }

  if (verified.length > 1) {
    findings.push({ level: 'ok', message: 'Every signature in the chain is verified by its issuer.' });
  }

  verified.forEach((link, index) => {
    const certificate = link.certificate;
    const validFrom = new Date(certificate.validFrom);
    const validTo = new Date(certificate.validTo);
    if (now < validFrom) {
      findings.push({ level: 'error', message: `"${name(certificate.subject)}" is not valid until ${validFrom.toUTCString()}.` });
    } else if (now > validTo) {
      findings.push({ level: 'error', message: `"${name(certificate.subject)}" expired on ${validTo.toUTCString()}.` });
    } else if (validTo.getTime() - now.getTime() < EXPIRY_WARNING_DAYS * DAY_MS) {
      findings.push({ level: 'warning', message: `"${name(certificate.subject)}" expires on ${validTo.toUTCString()}.` });
    }
    if (index > 0 && !certificate.ca) {
      findings.push({ level: 'error', message: `"${name(certificate.subject)}" issues certificates but is not marked as a CA.` });
    }
  });

  const status = findings.some(finding => finding.level === 'error')
    ? 'invalid'
    : findings.some(finding => finding.level === 'warning') ? 'warning' : 'valid';

  return { chain, others, anchorIndex, status, trustSource: trust.source, findings };
}