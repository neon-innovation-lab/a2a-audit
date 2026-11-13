# a2a-audit

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0_Compliant-purple.svg)](https://sarifweb.azurewebsites.net/)
[![A2A Protocol](https://img.shields.io/badge/Protocol-Linux_Foundation_A2A-orange.svg)](https://github.com/a2aproject/A2A)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-blue.svg)](https://nodejs.org/)
[![Pro Edition](https://img.shields.io/badge/Enterprise_Pro-Available-emerald.svg)](https://neoninnovationlab.com/a2a-pro)

**Zero-dependency DevSecOps static security scanner and SARIF linter for Agent2Agent (A2A) Agent Cards (`/.well-known/agent-card.json`).**

Audits Agent Cards against the official **Linux Foundation LF AI & Data / Google Cloud Agent2Agent specification**, detecting unauthenticated dangerous skills, cryptographic spoofing, SSRF vulnerabilities, adversarial prompt injection in metadata, and deprecated authentication flows in under **200 milliseconds**.

---

## ⚡ Quick Start

Scan any local file instantly with zero installation:

```bash
# Scan local Agent Card during development (Free Community Edition)
npx a2a-audit ./.well-known/agent-card.json

# Scan remote live agent card (Pro)
npx a2a-audit scan https://agent.example.com/.well-known/agent-card.json --key A2A-PRO-...

# Export OASIS SARIF 2.1.0 for GitHub Code Scanning (Pro)
npx a2a-audit ./agent-card.json --format sarif -o results.sarif --key A2A-PRO-...
```

---

## 💎 Free vs. Pro Enterprise Edition

| Capability | Free Community Edition | Pro Enterprise Edition ($19/mo or $99 lifetime) |
|---|---|---|
| **Local File Auditing** | ✅ Yes | ✅ Yes |
| **Trust Score (0-100) & Letter Grade** | ✅ Yes | ✅ Yes |
| **A2A Specification AST Linting** | ✅ Yes (Top 3 findings) | ✅ **100% Unrestricted Findings** |
| **Automated Code Remediation Snippets** | 🔒 Locked | ✅ **Full In-line Fix Snippets** |
| **Live Remote URL Scanning** (`https://...`) | 🔒 Locked | ✅ **Live Network Endpoint Auditing** |
| **OASIS SARIF 2.1.0 CI/CD Export** | 🔒 Locked | ✅ **Native GitHub Advanced Security Export** |
| **Cryptographic Offline License** | N/A | ✅ **Air-Gapped & Offline CI/CD Compatible** |
| **Priority Enterprise Support** | Community GitHub | ✅ **Direct Engineering Channel** |

👉 **[Unlock A2A-PRO Enterprise License](https://neoninnovationlab.com/a2a-pro)**

---

## 🔑 Activating Your Pro License

You can activate your Pro license in one of three ways:

### 1. Command Line Flag
```bash
npx a2a-audit agent-card.json --format sarif --key A2A-PRO-XXXX-XXXX-XXXX
```

### 2. Environment Variable
```bash
export A2A_LICENSE_KEY="A2A-PRO-XXXX-XXXX-XXXX"
npx a2a-audit scan https://agent.domain.com/.well-known/agent-card.json
```

### 3. GitHub Actions Secret
Set repository secret `A2A_LICENSE_KEY` in GitHub Settings → Secrets and variables → Actions.

---

## 🛡️ Why A2A Security Matters in 2026

The **Agent2Agent (A2A)** protocol has emerged as the global enterprise standard for autonomous inter-agent communication, backed by Google Cloud, IBM Research, Microsoft, AWS, Salesforce, and the Linux Foundation.

While Model Context Protocol (MCP) connects agents *downward* to internal tools, A2A connects agents *laterally* across corporate boundaries. The single entry point, identity passport, and capability contract for every A2A agent is its **Agent Card** (`/.well-known/agent-card.json`).

A compromised or misconfigured Agent Card exposes orchestrators and multi-agent meshes to:
- **Agent Impersonation & Spoofing**: Unsigned cards allowing MITM attackers to masquerade as trusted banking, billing, or ERP agents.
- **Server-Side Request Forgery (SSRF)**: Interface endpoints pointing to `localhost`, RFC 1918 private subnets, or cloud metadata services (`169.254.169.254`).
- **Prompt Injection in Metadata**: Adversarial instructions hidden in agent descriptions or skill examples that hijack orchestrator LLMs during routing.
- **Unauthenticated Dangerous Primitives**: Anonymous execution of high-privilege operations (shell commands, SQL queries, fund transfers).

---

## ⚖️ Architecture Comparison: a2a-audit vs. Alternatives

| Feature | `a2a-audit` (This Tool) | Cisco `a2a-scanner` | Pipelock / Network Proxies |
|---|---|---|---|
| **Runtime Dependencies** | **0 (Zero)** | Heavy (Python 3.11+, UV, YARA C-libs) | Docker / Sidecar Proxy |
| **Execution Latency** | **< 200 ms** | 15 – 30 seconds | Runtime overhead on every request |
| **LLM API Key Required** | **None (Deterministic AST)** | Yes (Requires OpenAI/Anthropic API) | None |
| **Native SARIF 2.1.0** | **Yes (1-click GitHub Security tab)** | Custom JSON / Terminal only | No (Emits log receipts) |
| **CI/CD Pull Request Gating** | **1-line GitHub Action** | Complex multi-step Python setup | Daemon deployment required |
| **False Positive Rate** | **0% (Spec-grounded AST rules)** | High (LLM semantic hallucinations) | N/A (Runtime firewall) |

---

## 🚀 GitHub Actions CI/CD Integration

Block pull requests that introduce insecure or non-compliant Agent Cards and populate GitHub Advanced Security alerts automatically:

```yaml
name: "A2A Security Gate"

on:
  pull_request:
    paths:
      - "**/.well-known/agent-card.json"
      - "**/agent-card.json"

jobs:
  audit-agent-card:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run a2a-audit
        uses: Ansarii/a2a-audit@v1
        with:
          card-path: "./.well-known/agent-card.json"
          format: "sarif"
          output-file: "a2a-results.sarif"
          fail-on: "high"
          license-key: ${{ secrets.A2A_LICENSE_KEY }}

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: "a2a-results.sarif"
```

---

## 📋 The 10 Core A2A Security Rules

| Rule ID | Severity | Category | Rule Trigger & Protocol Requirement |
|---|---|---|---|
| `A2A-SEC-001` | **CRITICAL** | `AGENT_SPOOFING` | **Unsigned Agent Card**: Missing cryptographic JWS signatures in `signatures`. Violates RFC 7515 / A2A Spec §8.4. |
| `A2A-SEC-002` | **CRITICAL** | `CRYPTO_INTEGRITY` | **Insecure Signature**: Algorithm is `none` or symmetric `HS256`, or `jku` origin does not match the provider domain. |
| `A2A-SEC-003` | **HIGH** | `CLEARTEXT_TRANSPORT` | **Insecure HTTP**: Any endpoint in `supportedInterfaces`, provider, or auth metadata uses `http://` instead of `https://` (Spec §13.4). |
| `A2A-SEC-004` | **CRITICAL** | `SSRF_EXPOSURE` | **Internal SSRF Exposure**: Interface or webhook points to `localhost`, RFC 1918 private IPs, or cloud metadata (`169.254.169.254`). |
| `A2A-SEC-005` | **HIGH** | `PROMPT_INJECTION` | **Adversarial Directives**: System prompt override phrases or zero-width Unicode obfuscation detected in metadata or skill examples. |
| `A2A-SEC-006` | **HIGH** | `DANGEROUS_PRIMITIVES` | **Unauthenticated Dangerous Skills**: High-privilege actions (shell, sql, payments) lack `securityRequirements`. |
| `A2A-SEC-007` | **MEDIUM** | `DEPRECATED_AUTH` | **Deprecated OAuth Flows**: Declares `implicit` or `password` (ROPC) flows, officially deprecated in `a2a.proto`. |
| `A2A-SEC-008` | **MEDIUM** | `CREDENTIAL_LEAK` | **Query Param API Key**: API key location is `"query"`, exposing secrets in web server logs and HTTP referrers. |
| `A2A-SEC-009` | **HIGH** | `CAPABILITY_ESCALATION` | **Unauthenticated Extended Card**: Declares `extendedAgentCard: true` without required authentication schemes (Spec §13.3). |
| `A2A-SEC-010` | **LOW** | `SPEC_COMPLIANCE` | **Schema Compliance**: Missing REQUIRED Protobuf fields (`name`, `description`, `version`, `supportedInterfaces`, `skills`). |

---

## 💻 Programmatic Node.js / TypeScript SDK

Integrate `a2a-audit` directly into your agent frameworks, registries, or verification pipelines:

```typescript
import { auditAgentCard, formatTerminalReport, formatSarifReport, verifyLicenseKey } from 'a2a-audit';

// Audit a local file or remote URL
const report = await auditAgentCard('./agent-card.json', {
  strict: true,
  timeoutMs: 5000
});

console.log(`Trust Score: ${report.trustScore}/100 (Grade: ${report.grade})`);
console.log(`Status: ${report.passed ? 'PASSED' : 'FAILED'}`);

// Format terminal report with optional license status
const licenseStatus = verifyLicenseKey(process.env.A2A_LICENSE_KEY);
console.log(formatTerminalReport(report, licenseStatus));
```

---

## ☁️ Cloud Fleet Surveillance (Apify Actor)

For continuous automated surveillance across partner agent directories, run the **A2A Agent Card Security Scanner** on Apify Store:

- **Pay-Per-Event (PPE)**: \$0.03 start + \$0.05 per audited card.
- **Automated Alerts**: Webhook alerts to Slack, Microsoft Teams, or PagerDuty when partner Agent Cards expire, drift, or fail compliance.

---

## 📄 License & Commercial Terms

Dual licensed under Apache-2.0 (Community Edition) and Commercial License (Enterprise Pro Edition).
Built with pride by [Neon Innovation Lab](https://neoninnovationlab.com). For custom audits or enterprise fleet licensing, contact support@neoninnovationlab.com.
