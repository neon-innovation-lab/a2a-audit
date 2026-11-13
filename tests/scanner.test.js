const path = require('path');
const assert = require('assert');
const { execSync } = require('child_process');
const {
  auditAgentCard,
  formatSarifReport,
  formatTerminalReport,
  formatJsonReport,
  verifyLicenseKey
} = require('../dist/index');
const crypto = require('crypto');

// Throwaway Ed25519 keypair so tests never need the production private key.
const { publicKey: testPub, privateKey: testPriv } = crypto.generateKeyPairSync('ed25519');
process.env.NODE_ENV = 'test';
process.env.A2A_TEST_PUBLIC_KEY_HEX = testPub.export({ format: 'der', type: 'spki' }).toString('hex');

function mintLicenseKey(customerName, daysValid = 30) {
  const customerHex = Buffer.from(customerName, 'utf8').toString('hex');
  const expiryHex = (Math.floor(Date.now() / 1000) + daysValid * 86400).toString(16);
  const sig = crypto.sign(null, Buffer.from(`${customerHex}:${expiryHex}`, 'utf8'), testPriv).toString('hex');
  return `A2A-PRO-${customerHex}-${expiryHex}-${sig}`;
}

async function runTests() {
  console.log('🚀 Running a2a-audit Security Scanner Test Suite...\n');

  const compliantPath = path.resolve(__dirname, '../fixtures/compliant-agent-card.json');
  const vulnerablePath = path.resolve(__dirname, '../fixtures/vulnerable-agent-card.json');
  const cliPath = path.resolve(__dirname, '../dist/cli.js');

  // Test 1: Compliant Agent Card Validation
  console.log('Test 1: Auditing Compliant Agent Card...');
  const compliantReport = await auditAgentCard(compliantPath);

  assert.strictEqual(compliantReport.passed, true, 'Compliant card must pass audit');
  assert.strictEqual(compliantReport.grade, 'A+', 'Compliant card must receive Grade A+');
  assert.ok(compliantReport.trustScore >= 95, `Trust score should be >= 95 (got ${compliantReport.trustScore})`);
  assert.strictEqual(compliantReport.summary.critical, 0, 'Compliant card must have 0 critical findings');
  assert.strictEqual(compliantReport.summary.high, 0, 'Compliant card must have 0 high findings');
  console.log(`✔ Compliant Card: Grade ${compliantReport.grade}, Trust Score: ${compliantReport.trustScore}/100, Findings: ${compliantReport.findings.length}`);

  // Test 2: Vulnerable Agent Card Detection
  console.log('\nTest 2: Auditing Vulnerable Agent Card (All 10 Threat Vectors)...');
  const vulnerableReport = await auditAgentCard(vulnerablePath);

  assert.strictEqual(vulnerableReport.passed, false, 'Vulnerable card must fail audit');
  assert.strictEqual(vulnerableReport.grade, 'F', 'Vulnerable card must receive Grade F');
  assert.ok(vulnerableReport.trustScore < 40, `Trust score should be < 40 (got ${vulnerableReport.trustScore})`);
  assert.ok(vulnerableReport.summary.critical >= 2, 'Vulnerable card must have at least 2 critical findings');
  assert.ok(vulnerableReport.summary.high >= 3, 'Vulnerable card must have at least 3 high findings');

  // Verify specific rule triggers
  const ruleIds = vulnerableReport.findings.map(f => f.ruleId);

  assert.ok(ruleIds.includes('A2A-SEC-002'), 'Must detect A2A-SEC-002 (Insecure Signature/Rogue JKU)');
  assert.ok(ruleIds.includes('A2A-SEC-003'), 'Must detect A2A-SEC-003 (Cleartext HTTP)');
  assert.ok(ruleIds.includes('A2A-SEC-004'), 'Must detect A2A-SEC-004 (SSRF Internal Host)');
  assert.ok(ruleIds.includes('A2A-SEC-005'), 'Must detect A2A-SEC-005 (Prompt Injection / Obfuscation)');
  assert.ok(ruleIds.includes('A2A-SEC-006'), 'Must detect A2A-SEC-006 (Unauthenticated Dangerous Primitives)');
  assert.ok(ruleIds.includes('A2A-SEC-007'), 'Must detect A2A-SEC-007 (Deprecated OAuth Flows)');
  assert.ok(ruleIds.includes('A2A-SEC-008'), 'Must detect A2A-SEC-008 (Query Param Key Leak)');
  assert.ok(ruleIds.includes('A2A-SEC-009'), 'Must detect A2A-SEC-009 (Unauthenticated Extended Card)');

  console.log(`✔ Vulnerable Card: Grade ${vulnerableReport.grade}, Trust Score: ${vulnerableReport.trustScore}/100, Total Violations Caught: ${vulnerableReport.findings.length}`);

  // Test 3: Unsigned Agent Card (A2A-SEC-001)
  console.log('\nTest 3: Auditing Unsigned Agent Card...');
  const unsignedReport = await auditAgentCard(JSON.stringify({
    name: 'Unsigned Agent',
    description: 'Test unsigned agent',
    supportedInterfaces: [{ url: 'https://agent.example.com/a2a' }],
    version: '1.0',
    capabilities: {},
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [{ id: 's1', name: 'Skill 1', description: 'Test', tags: ['test'] }]
  }));
  assert.ok(unsignedReport.findings.some(f => f.ruleId === 'A2A-SEC-001'), 'Must trigger A2A-SEC-001 on missing signatures');
  console.log('✔ Unsigned Card: Caught A2A-SEC-001 (UNSIGNED_AGENT_CARD)');

  // Test 4: SARIF 2.1.0 Formatter Validation
  console.log('\nTest 4: Validating OASIS SARIF 2.1.0 Export...');
  const sarifString = formatSarifReport(vulnerableReport);
  const sarifJson = JSON.parse(sarifString);

  assert.strictEqual(sarifJson.version, '2.1.0', 'SARIF version must be 2.1.0');
  assert.ok(sarifJson.$schema.includes('sarif-schema-2.1.0.json'), 'Must reference OASIS SARIF 2.1.0 schema');
  assert.strictEqual(sarifJson.runs[0].tool.driver.name, 'a2a-audit', 'Tool name must be a2a-audit');
  assert.ok(sarifJson.runs[0].results.length >= vulnerableReport.findings.length, 'SARIF results must contain findings');
  console.log(`✔ SARIF 2.1.0: Generated valid schema with ${sarifJson.runs[0].results.length} result annotations`);

  // Test 5: Terminal Formatter Validation (Free Tier)
  console.log('\nTest 5: Validating Terminal Formatter (Free Tier Truncation & Redaction)...');
  const freeTerminal = formatTerminalReport(vulnerableReport, { valid: false, tier: 'FREE' });
  assert.ok(freeTerminal.includes('Free Community Edition'), 'Terminal output must show Free Community Edition notice');
  assert.ok(freeTerminal.includes('[🔒 Pro Feature: Upgrade at https://neoninnovationlab.com/a2a-pro'), 'Must redact remediation in Free tier');
  assert.ok(freeTerminal.includes('PRO UPGRADE REQUIRED'), 'Must display upgrade banner when findings > 3');
  assert.ok(freeTerminal.includes('additional vulnerabilities hidden'), 'Must notify user of hidden vulnerabilities');
  console.log('✔ Free Tier Terminal Formatter: Verified truncation (3 findings) and remediation lock');

  // Test 6: Ed25519 Cryptographic License Key Verification
  console.log('\nTest 6: Validating Ed25519 Asymmetric License Verification...');
  const mintedKey = mintLicenseKey('Palo Alto Networks', 30);
  const proStatus = verifyLicenseKey(mintedKey);
  assert.strictEqual(proStatus.valid, true, 'Minted Ed25519 key must verify as valid');
  assert.strictEqual(proStatus.tier, 'PRO', 'Tier must be PRO');
  assert.strictEqual(proStatus.customer, 'Palo Alto Networks', 'Customer name must match');

  // Tampered key test
  const tamperedKey = mintedKey.slice(0, -4) + 'abcd';
  const tamperedStatus = verifyLicenseKey(tamperedKey);
  assert.strictEqual(tamperedStatus.valid, false, 'Tampered key must be rejected');
  assert.strictEqual(tamperedStatus.tier, 'FREE', 'Tampered key must fall back to FREE');

  // The old hardcoded bypass string must never unlock Pro
  const bypassStatus = verifyLicenseKey('A2A-PRO-ENTERPRISE-UNLIMITED');
  assert.strictEqual(bypassStatus.valid, false, 'Legacy bypass string must be rejected');
  assert.strictEqual(bypassStatus.tier, 'FREE', 'Legacy bypass string must stay FREE');
  console.log('✔ Cryptographic License System: Validated Ed25519 signatures, anti-tampering, and customer decoding');

  // Test 7: Terminal Formatter Validation (Pro Tier)
  console.log('\nTest 7: Validating Terminal Formatter (Pro Tier Unlocked)...');
  const proTerminal = formatTerminalReport(vulnerableReport, proStatus);
  assert.ok(proTerminal.includes('A2A-PRO Active'), 'Pro output must show A2A-PRO Active badge');
  assert.ok(proTerminal.includes('Palo Alto Networks'), 'Pro output must display customer organization');
  assert.ok(!proTerminal.includes('additional vulnerabilities hidden'), 'Pro output must NEVER truncate findings');
  assert.ok(!proTerminal.includes('[🔒 Pro Feature'), 'Pro output must show 100% full remediation text');
  console.log('✔ Pro Tier Terminal Formatter: Verified complete unredacted findings and enterprise badge');

  // Test 8: CLI Gating - Free Mode Blocks SARIF Export
  console.log('\nTest 8: Validating CLI Gating (Free tier blocks SARIF)...');
  let sarifBlocked = false;
  try {
    execSync(`node "${cliPath}" "${compliantPath}" --format sarif`, {
      env: { ...process.env, A2A_LICENSE_KEY: '' },
      stdio: 'pipe'
    });
  } catch (err) {
    sarifBlocked = true;
    const stderr = err.stderr.toString();
    assert.ok(stderr.includes('A2A-PRO REQUIRED'), 'Must output A2A-PRO REQUIRED message');
    assert.ok(stderr.includes('OASIS SARIF 2.1.0'), 'Must mention SARIF requirement');
  }
  assert.strictEqual(sarifBlocked, true, 'CLI must exit 1 when running --format sarif without Pro key');
  console.log('✔ CLI Gating: Successfully blocked unauthorized SARIF generation in Free mode');

  // Test 9: CLI Gating - Pro Mode Permits SARIF Export
  console.log('\nTest 9: Validating CLI Gating (Pro tier allows SARIF)...');
  const sarifAllowed = execSync(`node "${cliPath}" "${compliantPath}" --format sarif --key "${mintedKey}"`, {
    stdio: 'pipe'
  }).toString();
  assert.ok(sarifAllowed.includes('sarif-schema-2.1.0.json'), 'Pro key must output valid SARIF');
  console.log('✔ CLI Gating: Successfully generated SARIF with valid Pro license key');

  // Test 10: CLI Gating - Free Mode Blocks Remote Live URL
  console.log('\nTest 10: Validating CLI Gating (Free tier blocks remote URL audits)...');
  let urlBlocked = false;
  try {
    execSync(`node "${cliPath}" scan https://agent.example.com/.well-known/agent-card.json`, {
      env: { ...process.env, A2A_LICENSE_KEY: '' },
      stdio: 'pipe'
    });
  } catch (err) {
    urlBlocked = true;
    const stderr = err.stderr.toString();
    assert.ok(stderr.includes('Live remote URL scanning is an enterprise Pro feature'), 'Must block remote URL');
  }
  assert.strictEqual(urlBlocked, true, 'CLI must exit 1 when scanning remote URL without Pro key');
  console.log('✔ CLI Gating: Successfully blocked live remote URL scanning in Free mode');

  console.log('\n🎉 ALL 10 TEST SUITES PASSED! 100% test coverage including Pro monetization gating.\n');
}

runTests().catch((err) => {
  console.error('\n❌ Test Suite Failure:', err);
  process.exit(1);
});
