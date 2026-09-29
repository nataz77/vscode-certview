import { X509Certificate } from 'node:crypto';
import * as forge from 'node-forge';
import { parsePemCertificates } from './certificate';

export class PfxPasswordError extends Error {
  constructor(readonly passwordProvided: boolean) {
    super(passwordProvided ? 'The PKCS#12 password is incorrect.' : 'The PKCS#12 file is password protected.');
  }
}

function isPasswordError(error: unknown): boolean {
  return error instanceof Error && /MAC could not be verified|password/i.test(error.message);
}

function readPkcs12(data: Buffer, password: string | undefined): X509Certificate[] {
  let asn1: forge.asn1.Asn1;
  try {
    asn1 = forge.asn1.fromDer(forge.util.createBuffer(data.toString('binary')));
  } catch {
    throw new Error('The file is not a valid certificate, PEM bundle or PKCS#12 archive.');
  }

  const candidates = password === undefined ? ['', undefined] : [password];
  for (const candidate of candidates) {
    try {
      const pkcs12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, candidate as string);
      const bags = pkcs12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
      const certificates = bags.flatMap(bag => {
        const certificateAsn1 = bag.cert ? forge.pki.certificateToAsn1(bag.cert) : bag.asn1;
        return certificateAsn1
          ? [new X509Certificate(Buffer.from(forge.asn1.toDer(certificateAsn1).getBytes(), 'binary'))]
          : [];
      });
      if (certificates.length === 0) {
        throw new Error('The PKCS#12 file does not contain any certificate.');
      }
      return certificates;
    } catch (error) {
      if (!isPasswordError(error)) {
        throw error instanceof Error && error.message.startsWith('The PKCS#12')
          ? error
          : new Error(`Unable to read the PKCS#12 file: ${error instanceof Error ? error.message : 'unknown error'}`);
      }
    }
  }

  throw new PfxPasswordError(password !== undefined);
}

export function parseCertificateFile(data: Buffer, password?: string): X509Certificate[] {
  const text = data.toString('utf8');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    try {
      return parsePemCertificates(text);
    } catch {
      throw new Error('The file contains an invalid PEM certificate.');
    }
  }

  try {
    return [new X509Certificate(data)];
  } catch {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) {
      throw new Error('The file contains a private key but no certificate.');
    }
    return readPkcs12(data, password);
  }
}