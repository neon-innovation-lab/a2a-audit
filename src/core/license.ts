import * as crypto from 'crypto';

// Ed25519 Public Verification Key (RFC 8032 Asymmetric - Safe for public client distribution)
const PRODUCTION_PUBLIC_KEY_HEX =
  '302a300506032b65700321009dc55a8a1449008d8375289f07ae6da1ec2c3a88103733ec63034605c995e7e9';

// Test-only override so the unit tests can sign keys with a throwaway keypair.
// Ignored unless NODE_ENV is exactly "test".
function getPublicKeyHex(): string {
  return (process.env.NODE_ENV === 'test' && process.env.A2A_TEST_PUBLIC_KEY_HEX) || PRODUCTION_PUBLIC_KEY_HEX;
}

export interface LicenseStatus {
  valid: boolean;
  tier: 'FREE' | 'PRO';
  customer?: string;
  expiresAt?: string;
  message?: string;
}

/**
 * Validates an A2A-PRO cryptographic license key using Ed25519 asymmetric verification.
 * Format: A2A-PRO-<CUSTOMER_HEX>-<TIMESTAMP_HEX>-<SIG_HEX>
 */
export function verifyLicenseKey(key?: string): LicenseStatus {
  const licenseKey = key || process.env.A2A_LICENSE_KEY || process.env.NEON_API_KEY;

  if (!licenseKey || typeof licenseKey !== 'string') {
    return {
      valid: false,
      tier: 'FREE',
      message: 'No license key provided (Free Community Edition)'
    };
  }

  const trimmed = licenseKey.trim();

  const parts = trimmed.split('-');
  if (parts.length !== 5 || parts[0] !== 'A2A' || parts[1] !== 'PRO') {
    return {
      valid: false,
      tier: 'FREE',
      message: 'Invalid license key format. Expected: A2A-PRO-<CUSTOMER>-<EXPIRY>-<SIG>'
    };
  }

  try {
    const customerHex = parts[2];
    const expiryHex = parts[3];
    const sigHex = parts[4];

    const customer = Buffer.from(customerHex, 'hex').toString('utf8');
    const expiryEpoch = parseInt(expiryHex, 16);
    const nowEpoch = Math.floor(Date.now() / 1000);

    if (isNaN(expiryEpoch) || expiryEpoch < nowEpoch) {
      return {
        valid: false,
        tier: 'FREE',
        customer,
        message: 'License key has expired. Please renew at https://neoninnovationlab.com/a2a-pro'
      };
    }

    const payload = `${customerHex}:${expiryHex}`;
    const pubKeyDer = Buffer.from(getPublicKeyHex(), 'hex');
    const pubKey = crypto.createPublicKey({ key: pubKeyDer, format: 'der', type: 'spki' });

    const isValid = crypto.verify(
      null,
      Buffer.from(payload, 'utf8'),
      pubKey,
      Buffer.from(sigHex, 'hex')
    );

    if (!isValid) {
      return {
        valid: false,
        tier: 'FREE',
        message: 'Cryptographic signature verification failed. Invalid license key.'
      };
    }

    const expiresDate = new Date(expiryEpoch * 1000).toISOString().split('T')[0];

    return {
      valid: true,
      tier: 'PRO',
      customer,
      expiresAt: expiresDate
    };
  } catch {
    return {
      valid: false,
      tier: 'FREE',
      message: 'Malformed license key.'
    };
  }
}
