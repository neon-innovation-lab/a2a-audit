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
export declare function verifyLicenseKey(key?: string): LicenseStatus;
//# sourceMappingURL=license.d.ts.map