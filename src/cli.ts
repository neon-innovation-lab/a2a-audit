#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { auditAgentCard } from './core/scanner';
import { verifyLicenseKey } from './core/license';
import { formatTerminalReport } from './formatters/terminal';
import { formatJsonReport } from './formatters/json';
import { formatSarifReport } from './formatters/sarif';
import { SeverityLevel } from './types';

function printHelp(): void {
  console.log(`
a2a-audit - Zero-Dependency DevSecOps Scanner for Agent2Agent (A2A) Cards

USAGE:
  $ npx a2a-audit <target> [options]
  $ npx a2a-audit scan <target> [options]

ARGUMENTS:
  <target>                  Local file path or remote URL to agent-card.json
                            (e.g. https://agent.example.com/.well-known/agent-card.json)

OPTIONS:
  --key, -k <key>           A2A-PRO License Key (or set A2A_LICENSE_KEY env var)
  --format, -f <type>       Output format: "terminal", "json", "sarif" (default: "terminal")
  --output, -o <file>       Write audit report to specified file
  --fail-on <level>         Fail (exit 1) if findings match severity: "critical", "high", "medium", "low" (default: "high")
  --strict                  Enable strict gating: fail on any MEDIUM findings
  --timeout <ms>            HTTP request timeout in milliseconds (default: 10000)
  --help, -h                Show this help screen
  --version, -v             Display scanner version

EDITIONS & LICENSING:
  • Community Edition (Free):
    - Scans local agent card files
    - Calculates Trust Score & Security Grade
    - Truncates findings to 3 items and redacts code remediation fixes

  • Enterprise Pro ($19/mo or $99 lifetime):
    - Unlocks live remote URL scanning (e.g. https://agent.domain.com/...)
    - Unlocks OASIS SARIF 2.1.0 export for GitHub Advanced Security
    - Unlocks 100% of findings with full code remediation snippets
    - Get an instant key: https://neoninnovationlab.com/a2a-pro

EXAMPLES:
  # Scan local Agent Card (Free)
  $ npx a2a-audit ./.well-known/agent-card.json

  # Scan remote live agent card (Pro)
  $ npx a2a-audit scan https://agent.domain.com/.well-known/agent-card.json --key A2A-PRO-...

  # Export SARIF for GitHub Advanced Security (Pro)
  $ npx a2a-audit agent-card.json --format sarif -o results.sarif --key A2A-PRO-...
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('a2a-audit v1.1.0');
    process.exit(0);
  }

  let target = '';
  let format: 'terminal' | 'json' | 'sarif' = 'terminal';
  let outputPath: string | null = null;
  let strict = false;
  let failOn: SeverityLevel = 'HIGH';
  let timeoutMs = 10000;
  let licenseKey = process.env.A2A_LICENSE_KEY || process.env.NEON_API_KEY || '';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === 'scan') {
      continue;
    } else if (arg === '--key' || arg === '-k') {
      licenseKey = args[++i] || '';
    } else if (arg === '--format' || arg === '-f') {
      const val = (args[++i] || '').toLowerCase();
      if (val === 'json' || val === 'sarif' || val === 'terminal') {
        format = val;
      }
    } else if (arg === '--output' || arg === '-o') {
      outputPath = args[++i];
    } else if (arg === '--strict') {
      strict = true;
    } else if (arg === '--fail-on') {
      const level = (args[++i] || '').toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(level)) {
        failOn = level as SeverityLevel;
      }
    } else if (arg === '--timeout') {
      const t = parseInt(args[++i], 10);
      if (!isNaN(t) && t > 0) timeoutMs = t;
    } else if (!target && !arg.startsWith('-')) {
      target = arg;
    }
  }

  if (!target) {
    console.error('Error: No target specified. Please provide a file path or URL to an Agent Card.');
    printHelp();
    process.exit(1);
  }

  const isRemote = target.startsWith('http://') || target.startsWith('https://');
  const licenseStatus = verifyLicenseKey(licenseKey);

  // Pro Feature Gate 1: Remote Live URL Scanning
  if (isRemote && !licenseStatus.valid) {
    console.error('\n❌ [A2A-PRO REQUIRED] Live remote URL scanning is an enterprise Pro feature.');
    console.error('   Free Community Edition can scan local files on disk.');
    console.error('');
    console.error('   To scan live agent endpoints:');
    console.error('   1. Pass your license key: npx a2a-audit scan <url> --key <A2A-PRO-KEY>');
    console.error('   2. Or set environment variable: export A2A_LICENSE_KEY=<A2A-PRO-KEY>');
    console.error('   3. Get an instant license at: https://neoninnovationlab.com/a2a-pro\n');
    process.exit(1);
  }

  // Pro Feature Gate 2: OASIS SARIF 2.1.0 Export
  if (format === 'sarif' && !licenseStatus.valid) {
    console.error('\n❌ [A2A-PRO REQUIRED] OASIS SARIF 2.1.0 GitHub Advanced Security export is an enterprise Pro feature.');
    console.error('   Free Community Edition supports --format terminal and --format json.');
    console.error('');
    console.error('   To enable SARIF CI/CD reporting:');
    console.error('   1. Pass your license key: npx a2a-audit <target> --format sarif --key <A2A-PRO-KEY>');
    console.error('   2. Or set GitHub Actions secret: A2A_LICENSE_KEY');
    console.error('   3. Get an instant license at: https://neoninnovationlab.com/a2a-pro\n');
    process.exit(1);
  }

  try {
    const report = await auditAgentCard(target, { strict, failOn, timeoutMs });

    let outputText = '';
    switch (format) {
      case 'json':
        outputText = formatJsonReport(report, licenseStatus);
        break;
      case 'sarif':
        outputText = formatSarifReport(report);
        break;
      case 'terminal':
      default:
        outputText = formatTerminalReport(report, licenseStatus);
        break;
    }

    if (outputPath) {
      const fullPath = path.resolve(process.cwd(), outputPath);
      fs.writeFileSync(fullPath, outputText, 'utf8');
      if (format === 'terminal') {
        console.log(outputText);
      }
      console.log(`\nAudit report written to: ${fullPath}`);
    } else {
      console.log(outputText);
    }

    if (format === 'terminal' && !licenseStatus?.valid) {
      console.log('\n[a2a-audit] Need automated GitHub SARIF CI/CD policy gating ($49)? https://neoninnovationlab.com/checkout?item=a2a_pro_ci');
      console.log('[a2a-audit] Need a hardened production MCP + A2A server? https://neoninnovationlab.com/mcp-development');
    }

    // Determine exit code
    let shouldFail = !report.passed;
    if (failOn === 'CRITICAL') {
      shouldFail = report.summary.critical > 0;
    } else if (failOn === 'HIGH') {
      shouldFail = report.summary.critical > 0 || report.summary.high > 0;
    } else if (failOn === 'MEDIUM') {
      shouldFail = report.summary.critical > 0 || report.summary.high > 0 || report.summary.medium > 0;
    }

    process.exit(shouldFail ? 1 : 0);
  } catch (err: any) {
    console.error(`Fatal scanner error: ${err.message}`);
    process.exit(1);
  }
}

main();
