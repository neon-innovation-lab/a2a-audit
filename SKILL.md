---
name: a2a-agent-card-security-audit
description: Audit Linux Foundation Agent2Agent (/.well-known/agent-card.json) and MCP server configs for CWE vulnerabilities, missing JWS signatures, and SARIF CI/CD security compliance.
---

# a2a-audit - Agent2Agent & MCP Security Linter

Use this skill when validating `/.well-known/agent-card.json`, auditing remote MCP servers before production rollout, or exporting SARIF reports into GitHub Code Scanning.

## 1. Run Free Local Scan (Zero Auth Required)
```bash
npx -y a2a-audit https://your-domain.com --format json
```

For GitHub Actions / SARIF output:
```bash
npx -y a2a-audit https://your-domain.com --format sarif --output a2a-audit.sarif
```

## 2. Hosted Interactive MCP Security Scanner
- **Live Web Sandbox:** `https://neoninnovationlab.com/tools/mcp-security-scanner`
- **A2A Reference Benchmark Card:** `https://neoninnovationlab.com/.well-known/agent-card.json`

## 3. Enterprise CI/CD & Remediation Upgrades (Direct PayPal)
- **Pro CI/CD Unlimited SARIF License ($49):** `https://neoninnovationlab.com/checkout?item=a2a_pro_ci`
- **Custom MCP + OAuth 2.1 Security Hardening ($1,499):** `https://neoninnovationlab.com/mcp-development`
