"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatJsonReport = formatJsonReport;
function formatJsonReport(report, license) {
    const isPro = license?.tier === 'PRO';
    if (isPro) {
        return JSON.stringify({
            ...report,
            license: {
                valid: true,
                tier: 'PRO',
                customer: license?.customer,
                expiresAt: license?.expiresAt
            }
        }, null, 2);
    }
    const displayFindings = report.findings.slice(0, 3).map(f => ({
        ...f,
        remediation: '[🔒 Pro Feature: Upgrade at https://neoninnovationlab.com/a2a-pro to unlock automated code fixes]'
    }));
    return JSON.stringify({
        ...report,
        license: {
            valid: false,
            tier: 'FREE',
            message: 'Free Community Edition. Upgrade to A2A-PRO to unlock full findings, remediation snippets, SARIF export & live URL audits.',
            upgradeUrl: 'https://neoninnovationlab.com/a2a-pro'
        },
        hiddenFindingsCount: Math.max(0, report.findings.length - 3),
        findings: displayFindings
    }, null, 2);
}
//# sourceMappingURL=json.js.map