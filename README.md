# WaldoHunt

**Insider Threat SPL Generator for Splunk Enterprise Security**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

WaldoHunt is a practitioner-built detection engineering tool that generates production-ready Splunk Processing Language (SPL) searches for insider threat detection. Grounded in the CERT/CC Insider Threat Framework, it walks analysts through a guided wizard — environment, attack pattern, activity type, and log source configuration — and outputs correlation-ready SPL mapped to MITRE ATT&CK TTPs.

---

## What It Does

- **Guided wizard** — 5-step flow: environment → CERT attack pattern → activity → log source config → multi-tab output
- **8 CERT/CC patterns** — IT Sabotage, IP Theft, Fraud, Espionage, Data Manipulation, Third-Party/Contractor, Unauthorized Disclosure, Workplace Violence/Harassment
- **60 detection templates** — each with full SPL (AWS + On-Prem), MITRE ATT&CK mapping, and log source recommendations
- **Multi-environment support** — AWS Cloud, On-Prem/Hybrid with 24 log sources
- **Live index/sourcetype overrides** — analysts enter actual Splunk index names and sourcetypes; SPL updates in real time
- **Multi-SIEM export** — SPL, Sigma (YAML), KQL (Microsoft Sentinel), YARA-L (Google Chronicle), EQL (Elastic), Datadog JSON
- **Production readiness** — correlation search configs, RBA risk scoring, deployment checklists, suppression rules, alert volume projections
- **Testing & validation** — synthetic event generator with expected output samples
- **Threat-informed** — adversary emulation mapping to APT groups, intel gap analysis, campaign-based detection bundles
- **Compliance mapping** — NIST 800-53, CIS Controls v8, GDPR, PCI DSS, ISO 27001, HIPAA, SOX
- **CI/CD ready** — GitHub Actions workflow, Detection-as-Code bundles, batch export

---

## CERT/CC Insider Threat Patterns Covered

| Pattern | Activities | Coverage |
|---|---|---|
| IT Sabotage | 10 | Mass deletion, resource destruction, config tampering, logic bombs, backup destruction, access revocation, ransomware deployment, system degradation, certificate manipulation, network reconfiguration |
| IP Theft | 11 | Bulk downloads, repo cloning, secrets access, data staging, cross-account movement, USB exfiltration, email exfiltration, print exfiltration, cloud sync, screen capture, database dump |
| Fraud | 9 | Privilege escalation, unauthorized provisioning, policy bypass, account creation, log tampering, billing manipulation, payroll manipulation, vendor collusion, expense fraud |
| Espionage | 8 | Reconnaissance, credential harvesting, sensitive data access, lateral movement, C2 channels, persistence, document hoarding, meeting infiltration |
| Data Manipulation | 6 | Report falsification, model poisoning, transaction manipulation, record alteration, data poisoning, metric/KPI manipulation |
| Third-Party / Contractor | 7 | Vendor account abuse, MSP pivoting, credential sharing, partner portal scraping, supply chain insertion, after-hours access, post-engagement backdoor |
| Unauthorized Disclosure | 6 | Media/regulatory leaks, whistleblower collection, social media posting, competitor data transfer, evidence destruction, regulatory filing manipulation |
| Workplace Violence | 3 | Digital stalking/tracking, threatening communications, unauthorized surveillance |

---

## Log Sources

### AWS Cloud
CloudTrail, S3 Access Logs, VPC Flow Logs, GuardDuty, IAM Access Analyzer, AWS Config, CloudWatch Logs, Macie, Security Hub, CodeCommit

### On-Prem / Hybrid
Active Directory, Windows Security, DLP (Symantec), EDR (CrowdStrike), Proxy/Web Gateway, SIEM Correlation, Email Gateway, Print Service, Database Audit, VPN/ZTNA, Physical Badge Access, Calendar, HRIS, Financial/ERP

---

## Quick Start

### Requirements

- Node.js 20+
- Docker Engine 20.10+ (optional, for containerized deployment)
- Port 8080 (HTTP) and 8443 (HTTPS) available on the host

### Development

```bash
git clone https://github.com/mshermancyber/Waldo-Hunt.git
cd waldo-hunt
npm install
npm run dev        # Vite dev server on port 5173
npm run build      # Production build → dist/
```

### Docker

```bash
docker compose up -d --build
# http://localhost:8080  — HTTP
# https://localhost:8443 — HTTPS (self-signed)
```

### Configuration

```bash
# Change ports via environment variables
HOST_HTTP_PORT=9090 HOST_HTTPS_PORT=9443 docker compose up -d
```

---

## Project Structure

```
waldohunt/
├── src/
│   ├── main.tsx              # React entry point
│   ├── App.tsx               # Root component — 5-step wizard
│   ├── types.ts              # TypeScript type definitions
│   ├── data/                 # Detection data layer
│   │   ├── activities.ts     # 60 activities across 8 CERT/CC patterns
│   │   ├── logSources.ts     # 24 log sources with recommendations
│   │   ├── splTemplates.ts   # 120 SPL templates (60 AWS + 60 On-Prem)
│   │   ├── mitreMap.ts       # MITRE ATT&CK TTP mappings
│   │   ├── sigmaTemplates.ts # Sigma rule templates
│   │   ├── kqlTemplates.ts   # Microsoft KQL templates
│   │   ├── yaraLTemplates.ts # Google Chronicle YARA-L
│   │   ├── eqlTemplates.ts   # Elastic Security EQL
│   │   ├── datadogTemplates.ts # Datadog Cloud SIEM
│   │   ├── threatActors.ts   # APT group adversary mappings
│   │   ├── campaignBundles.ts # Curated campaign detection sets
│   │   ├── playbooks.ts      # Response playbooks per detection
│   │   ├── fpGuidance.ts     # False positive guidance
│   │   ├── baselineWindows.ts # Baseline window calibration
│   │   ├── rbaConfig.ts      # Risk-Based Alerting configs
│   │   ├── correlationDefaults.ts # ES correlation search defaults
│   │   ├── complianceMapping.ts   # NIST/CIS control mappings
│   │   ├── regulatoryCompliance.ts # GDPR/PCI/HIPAA/SOX
│   │   ├── incidentTemplates.ts   # ServiceNow/Jira/SOAR tickets
│   │   ├── costEstimator.ts  # Splunk license cost estimator
│   │   ├── syntheticEvents.ts # Test event generator
│   │   ├── huntQueries.ts    # Ad-hoc pivot hunt SPL
│   │   └── ...               # Additional data modules
│   ├── components/           # React components (38 total)
│   │   ├── StepEnv.tsx       # Environment selector
│   │   ├── StepPattern.tsx   # Attack pattern selector
│   │   ├── StepActivity.tsx  # Activity checkboxes
│   │   ├── StepLogSources.tsx # Log source configuration
│   │   ├── StepOutput.tsx    # 16-tab output dashboard
│   │   └── ...               # SPLPanel, MITRETable, ExportPanel, etc.
│   └── hooks/
│       └── useWizardState.ts # Wizard state machine
├── nginx/
│   └── waldohunt.conf        # nginx config (HTTP + HTTPS)
├── Dockerfile                # Multi-stage build (Node → nginx)
├── docker-compose.yml        # Docker Compose config
├── package.json
├── tsconfig.json
├── vite.config.ts
├── LICENSE                   # GPL v3
└── README.md
```

---

## Output Tabs

The output page includes 16 tabs spanning the full detection lifecycle:

```
SPL | Testing | Hunt | Intel | Coverage | Roadmap | Cost | Compliance
Export | Platforms | Tickets | Deploy | Checklist | Playbook | Ops | Trace
```

---

## Security Notes

- The container runs nginx as a non-root user (nginx:alpine default)
- HTTP security headers configured in `nginx/waldohunt.conf`
- Content-Security-Policy with `script-src 'self'` (no `unsafe-inline` in production)
- This tool is read-only — it generates SPL but does not connect to any Splunk instance or external service
- No credentials, API keys, or sensitive data are processed or stored
- Suitable for internal network deployment; for external exposure, place behind a reverse proxy with valid TLS

---

## Tuning Generated SPL

The output searches are starting points. Before deploying to production Splunk ES:

1. **Validate index names** match your Splunk ingestion pipeline (use the override fields in Step 4)
2. **Check sourcetype values** against your actual CIM mappings
3. **Adjust thresholds** — default values are illustrative and need baseline calibration
4. **Populate lookup tables** — queries referencing `sensitive_resources`, `internal_buckets`, `known_corp_domains`, etc. require manual lookup table population
5. **Test in a non-production search head** before promoting to correlation searches
6. **Establish baselines** — use the Baseline Window Guidance in the Trace tab for calibration steps

---

## Built With

- React 18 + TypeScript
- Vite 6
- Docker (multi-stage: Node 20 → nginx:alpine)
- CERT/CC Insider Threat Framework (Carnegie Mellon University SEI)
- MITRE ATT&CK Enterprise Matrix
- Splunk Enterprise Security CIM 4.20

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

---

## Author

**Mark Sherman** · [@mshermancyber](https://linkedin.com/in/mshermancyber)  
Senior Cybersecurity Specialist — Detection Engineering · Insider Threat · SIEM

---

## Contributing

Contributions welcome. Areas of interest:

- Additional log source support (Okta, Azure AD, GCP, Kubernetes)
- Detection variants (UEBA-enhanced, low-and-slow, time-windowed correlation)
- New CERT/CC pattern coverage
- Translation quality improvements for non-SPL platforms

Please open an issue or pull request at [github.com/mshermancyber/Waldo-Hunt](https://github.com/mshermancyber/Waldo-Hunt).
