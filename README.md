# WaldoHunt

**Insider Threat SPL Generator for Splunk Enterprise Security**

WaldoHunt is a practitioner-built detection engineering tool that generates production-ready Splunk Processing Language (SPL) searches for insider threat detection. Grounded in the CERT/CC Insider Threat Framework, it walks analysts through a guided wizard — environment, attack pattern, activity type, and log source configuration — and outputs correlation-ready SPL mapped to MITRE ATT&CK TTPs.

---

## What It Does

- **Guided wizard** — 5-step flow: environment → CERT attack pattern → activity type → log source config → SPL output
- **Dual environment support** — AWS cloud-native (CloudTrail, GuardDuty, Macie, VPC Flow, etc.) and on-prem/hybrid (Active Directory, CrowdStrike EDR, Symantec DLP, proxy/web gateway)
- **Live index/sourcetype overrides** — analysts enter their actual Splunk index names and sourcetypes; SPL updates in real time
- **MITRE ATT&CK mapping** — every generated detection is mapped to relevant technique IDs, linked directly to attack.mitre.org
- **24 detection templates** across 4 CERT patterns: IT Sabotage, IP Theft, Fraud, and Espionage
- **One-click copy** — each SPL block is independently copyable for direct paste into Splunk ES correlation searches

---

## CERT/CC Attack Patterns Covered

| Pattern | Activities |
|---|---|
| IT Sabotage | Mass data deletion, resource destruction, config tampering, logic bombs, backup destruction, access revocation |
| IP Theft | Mass storage download, code repo clone, secrets access, data staging, cross-account movement, USB exfiltration |
| Fraud | Privilege escalation, unauthorized provisioning, policy bypass, account creation, log tampering, billing manipulation |
| Espionage | Enumeration/recon, credential harvesting, sensitive data access, lateral movement, C2 channels, persistence |

---

## AWS Log Sources

| Source | Splunk Index | Coverage |
|---|---|---|
| AWS CloudTrail | `aws_cloudtrail` | API call history — core source for all insider threat detection |
| S3 Access Logs | `aws_s3_accesslogs` | Object-level GET/PUT/DELETE with requester identity |
| VPC Flow Logs | `aws_vpcflow` | Network traffic metadata for exfiltration/C2 detection |
| GuardDuty | `aws_guardduty` | Pre-built threat intelligence findings |
| IAM Access Analyzer | `aws_iam` | Policy changes, key creation, cross-account trusts |
| AWS Config | `aws_config` | Configuration change history |
| CloudWatch Logs | `aws_cloudwatch` | Application/Lambda logs |
| Amazon Macie | `aws_macie` | S3 sensitive data discovery findings |
| Security Hub | `aws_securityhub` | Aggregated cross-service findings |
| CodeCommit | `aws_codecommit` | Repository clone/pull/push activity |

## On-Prem Log Sources

| Source | Splunk Index | Coverage |
|---|---|---|
| Active Directory | `wineventlog` | Auth, group changes, account lifecycle |
| Windows Security | `wineventlog` | Logon (4624/4648), process (4688), object access (4663) |
| DLP (Symantec/FP) | `symantec_dlp` | Data movement policy violations |
| EDR (CrowdStrike) | `crowdstrike` | Process execution, file write, network, registry |
| Proxy/Web Gateway | `proxy` | HTTP/HTTPS requests, byte counts, URL categories |

---

## Project Structure

```
waldohunt/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .dockerignore
├── .gitignore
├── nginx/
│   └── waldohunt.conf
├── html/
│   ├── index.html       # WaldoHunt application
│   ├── logo.jpg         # Site logo
│   └── 404.html         # Custom 404 page
└── README.md
```

---

## Requirements

- Docker Engine 20.10+
- Docker Compose v2+ (`docker compose` — not `docker-compose`)
- Port 8080 available on the host (configurable)

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/mshermancyber/waldohunt.git
cd waldohunt
```

### 2. Configure environment (optional)

```bash
cp .env.example .env
# Edit .env to change the host port if needed (default: 8080)
```

### 3. Build and start

```bash
docker compose up -d --build
```

### 4. Open in browser

```
http://localhost:8080
```

---

## Configuration

### Change the host port

Edit `.env`:

```env
HOST_PORT=9090
```

Then restart:

```bash
docker compose down && docker compose up -d
```

### Run on a specific IP

Edit `docker-compose.yml`, change the ports entry:

```yaml
ports:
  - "192.168.1.100:8080:80"
```

### Reverse proxy (nginx / Traefik on host)

If you're putting WaldoHunt behind a reverse proxy, set `HOST_PORT` to a non-public port (e.g. `3000`) and proxy from your host nginx:

```nginx
location /waldohunt/ {
    proxy_pass http://127.0.0.1:3000/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

---

## Common Commands

```bash
# Build and start (detached)
docker compose up -d --build

# View logs
docker compose logs -f

# Stop
docker compose down

# Stop and remove volumes
docker compose down -v

# Restart after config change
docker compose restart waldohunt

# Shell into running container
docker compose exec waldohunt bash

# Check health status
docker compose ps

# Rebuild image only (no cache)
docker compose build --no-cache
```

---

## Development / Live Editing

To edit HTML without rebuilding the image, uncomment the volume mount in `docker-compose.yml`:

```yaml
volumes:
  - ./html:/var/www/waldohunt:ro
```

Then restart the container. Changes to files in `html/` will be reflected immediately.

---

## Security Notes

- The container runs nginx as `www-data` — not root
- HTTP security headers are set in `nginx/waldohunt.conf` (X-Frame-Options, X-Content-Type-Options, CSP, etc.)
- This tool is **read-only** — it generates SPL but does not connect to any Splunk instance or external service
- No credentials, API keys, or sensitive data are processed or stored
- Suitable for internal network deployment; if exposing externally, place behind a reverse proxy with TLS

---

## Tuning Generated SPL

The output searches are **starting points**. Before deploying to production Splunk ES:

1. **Validate index names** match your Splunk ingestion pipeline (use the override fields in Step 3)
2. **Check sourcetype values** against your actual CIM mappings
3. **Adjust thresholds** — default values (e.g. `download_count > 200`) are illustrative and will need baseline calibration
4. **Populate lookup tables** — queries referencing `sensitive_resources` and `internal_buckets` require manual lookup table population
5. **Test in a non-production search head** before promoting to correlation searches

---

## Built With

- Vanilla HTML/CSS/JavaScript — zero runtime dependencies, no build step
- Nginx 1.22+ on Debian 12 Slim
- CERT/CC Insider Threat Framework (Carnegie Mellon University SEI)
- MITRE ATT&CK Enterprise Matrix

---

## License

MIT License — see `LICENSE` for details.

---

## Author

**Mark Sherman** · [@mshermancyber](https://linkedin.com/in/mshermancyber)  
Senior Cybersecurity Specialist — Detection Engineering · Insider Threat · SIEM
