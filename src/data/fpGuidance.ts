// False positive guidance per detection type
// Expected noise levels, common FP scenarios, and exclusion recommendations

export interface FPGuidance {
  noiseLevel: 'low' | 'medium' | 'high' | 'critical';
  commonScenarios: string[];
  exclusions: string[];
  tuningTips: string[];
  expectedBaseline: string;
}

export const FP_GUIDANCE: Record<string, FPGuidance> = {
  delete_data: {
    noiseLevel: 'medium',
    commonScenarios: [
      'Automated CI/CD pipeline cleanup jobs — use known pipeline IAM roles in exclusion list',
      'Terraform/CloudFormation destroy operations — correlate with deployment windows',
      'Legitimate tiering/archival jobs moving data to Glacier — exclude by eventSource',
      'Test environment teardown during off-hours — but still worth investigating',
    ],
    exclusions: [
      'Exclude known automation roles (e.g., arn:aws:iam::*:role/ci-cd-*)',
      'Exclude events where sourceIPAddress is from approved CI/CD IP ranges',
      'Exclude DeleteObject operations within S3 lifecycle policy execution windows',
    ],
    tuningTips: [
      'Run this detection at mean + 3σ baseline for 14 days',
      'Create a lookup table of approved deletion windows per environment',
      'Correlate with change management ticket system if available',
      'Alert only when delete_count > 3σ AND bucket contains data tagged as production',
    ],
    expectedBaseline: 'Most environments: 50–500 deletes/day from automation. Manual deletes: 5–20/day.',
  },
  resource_destroy: {
    noiseLevel: 'medium',
    commonScenarios: [
      'Auto-scaling group terminations — exclude by instance profile ARN',
      'Infrastructure-as-Code destroy operations — Terraform, Pulumi, CDK',
      'Scheduled non-production environment teardowns (dev/staging night cleanup)',
      'DR/HA failover events causing old instances to terminate',
    ],
    exclusions: [
      'Exclude instances terminated by Auto Scaling Group lifecycle hooks',
      'Exclude destroy actions initiated by known deployment roles',
      'Filter out resource_destroy events in non-production accounts (if account tag available)',
    ],
    tuningTips: [
      'Correlate with change window calendar',
      'Flag TerminateInstances with multiple instance IDs in a single API call (bulk termination)',
      'Cross-reference with recent AssumeRole events from unusual IPs',
    ],
    expectedBaseline: '10–100 terminations/day in auto-scaling environments. Manual: 0–5/day.',
  },
  config_tamper: {
    noiseLevel: 'low',
    commonScenarios: [
      'Legitimate security team modifying SCPs during incident response',
      'Automated compliance tools adjusting bucket policies',
      'Network team updating security group rules during maintenance',
      'CloudTrail trail rotation/update during log pipeline maintenance',
    ],
    exclusions: [
      'Exclude events from security team IAM roles during declared change windows',
      'Exclude automated compliance tools (e.g., AWS Config auto-remediation)',
    ],
    tuningTips: [
      'CRITICAL: Alert immediately on StopLogging or DeleteTrail — no exclusions',
      'For bucket policy changes: verify the new policy does not grant public access',
      'Correlate SCP detachments with attached policy inventory changes',
    ],
    expectedBaseline: '0–5 policy changes/week in stable environments. Security group changes: higher but routine.',
  },
  s3_exfil: {
    noiseLevel: 'high',
    commonScenarios: [
      'Data engineering jobs processing large datasets — exclude known data pipeline roles',
      'ML training jobs reading training data from S3 — high byte count, expected',
      'Backup/replication jobs syncing buckets across regions',
      'Laptops syncing work files via S3-mounted drives',
      'Analysts running Athena queries against S3 (triggers GetObject)',
    ],
    exclusions: [
      'Exclude known data pipeline IAM roles',
      'Exclude requests from within VPC endpoints (internal traffic)',
      'Exclude GetObject calls where userAgent contains "Athena" or "Glue"',
      'Exclude requests to buckets tagged as staging/training/ml-data',
    ],
    tuningTips: [
      'Focus on GetObject (read) not PutObject (write)',
      'Correlate with user\'s historical download patterns (UEBA)',
      'Flag spikes: 10× the user\'s 30-day moving average',
      'Cross-reference with PII/PCI bucket tags from Macie',
    ],
    expectedBaseline: 'Data engineers: 1,000–50,000 GetObject/day. Regular users: 0–50/day.',
  },
  priv_escalation: {
    noiseLevel: 'low',
    commonScenarios: [
      'IAM administrator provisioning new users (legitimate) — exclude admin roles',
      'DevOps granting temporary elevated access during incident — check ticket correlation',
      'Service account creation for new application deployments',
      'JIT (just-in-time) access systems automatically attaching policies',
    ],
    exclusions: [
      'Exclude IAM admin roles performing user provisioning (arn:aws:iam::*:role/iam-admin-*)',
      'Exclude JIT access broker roles with known session tags',
    ],
    tuningTips: [
      'CRITICAL: Alert immediately on AttachUserPolicy with AdministratorAccess',
      'Correlate admin grants with off-hours activity (time-of-day anomaly)',
      'Monitor for AttachRolePolicy followed by AssumeRole within 5 minutes',
    ],
    expectedBaseline: '0–3 privilege changes/day in well-governed environments. Zero is achievable for non-admin users.',
  },
  recon: {
    noiseLevel: 'high',
    commonScenarios: [
      'New engineers exploring the environment (onboarding) — temporary, first-week expected',
      'Security tools performing asset discovery (e.g., Prowler, ScoutSuite)',
      'Cloud architects designing new services — broad Describe calls expected',
      'Third-party assessment tools running periodic audits',
    ],
    exclusions: [
      'Exclude known security assessment tools by userAgent string',
      'Exclude events during onboarding week for new IAM users (lookup new_hire table)',
      'Exclude IPs from approved vulnerability scanner ranges',
    ],
    tuningTips: [
      'Focus on first-time-service API calls (services never accessed by this user before)',
      'Correlate Describe API volume with subsequent destructive API calls',
      'Alert on services_probed > 8 OR unique_apis > 15 (above normal exploration)',
    ],
    expectedBaseline: 'New users: 100+ Describe calls in first week. Established users: 10–50/day across 2–3 services.',
  },
  credential_harvest: {
    noiseLevel: 'low',
    commonScenarios: [
      'Security tools performing credential audits (e.g., Steampipe, CloudTracker)',
      'Developers accessing secrets for legitimate application work',
      'Automated rotation jobs checking secret values before rotation',
    ],
    exclusions: [
      'Exclude GetSecretValue calls from within the same account (internal access)',
      'Exclude known secret rotation Lambda functions',
    ],
    tuningTips: [
      'CRITICAL: Alert on GetSecretValue + GetSessionToken from same user within 5 minutes',
      'Monitor for secrets accessed outside business hours (time anomaly)',
      'Flag access from IPs not in the user\'s 30-day history',
    ],
    expectedBaseline: '5–50 GetSecretValue/day for developers. Non-developers: 0.',
  },
  lateral_move: {
    noiseLevel: 'medium',
    commonScenarios: [
      'Cross-account CI/CD pipelines assuming deployment roles',
      'Federated single sign-on assuming roles across accounts',
      'SRE team accessing production from bastion accounts',
      'Automated DR testing failing over between regions/accounts',
    ],
    exclusions: [
      'Exclude known federated SSO role chains',
      'Exclude CI/CD deployment role assumptions from approved accounts',
    ],
    tuningTips: [
      'Alert on first-time cross-account AssumeRole (never-before-seen target account)',
      'Correlate AssumeRole with subsequent destructive API calls in target account',
      'Flag role chains exceeding 2 hops',
    ],
    expectedBaseline: '5–50 cross-account assumptions/day in multi-account setups. First-time: should be zero.',
  },
  usb_exfil: {
    noiseLevel: 'low',
    commonScenarios: [
      'IT staff using USB drives for system recovery/imaging',
      'Approved encrypted USB devices in high-security environments',
      'Print production teams moving files via USB to print servers',
    ],
    exclusions: [
      'Exclude authorized IT support accounts with USB exception',
      'Exclude known encrypted device serial numbers (lookup table)',
    ],
    tuningTips: [
      'Alert on USB write + immediate disconnect/unmount',
      'Correlate USB activity with file copy volume (high volume = higher risk)',
      'Flag USB use on systems not in the authorized exception list',
    ],
    expectedBaseline: '0 USB writes/day in most environments. IT exceptions: 1–5/day.',
  },
  c2_comms: {
    noiseLevel: 'high',
    commonScenarios: [
      'Software updates downloading from CDNs (Akamai, CloudFront, Fastly)',
      'Browser extensions beaconing to update servers',
      'IoT devices phoning home to vendor clouds',
      'DNS-over-HTTPS (DoH) traffic appearing as unusual HTTPS',
      'Backup/replication traffic to cloud storage endpoints',
    ],
    exclusions: [
      'Exclude traffic to known CDN ASNs (Akamai, CloudFront, Fastly, Cloudflare)',
      'Exclude traffic to major cloud provider IP ranges (AWS, Azure, GCP)',
      'Exclude known software update endpoints',
    ],
    tuningTips: [
      'Focus on beaconing patterns: regular intervals, consistent packet sizes',
      'JA3/JARM fingerprinting to detect C2 frameworks',
      'Long connections (> 1 hour) to non-standard ports',
      'Correlate with process creation events on the same host',
    ],
    expectedBaseline: 'Hundreds of unique destinations/day from web browsing. Focus on outliers: > 50 unique IPs in 1 hour.',
  },
  persistence: {
    noiseLevel: 'medium',
    commonScenarios: [
      'IT creating scheduled tasks for maintenance windows',
      'Service account provisioning by IAM automation',
      'Application installers creating scheduled update tasks',
    ],
    exclusions: [
      'Exclude scheduled tasks created by approved software deployment tools',
      'Exclude service accounts created by automated provisioning systems',
    ],
    tuningTips: [
      'Alert on persistence mechanisms created outside change windows',
      'Correlate scheduled task creation with user resignation/termination timeline',
      'Flag when a single user employs multiple persistence mechanisms simultaneously',
    ],
    expectedBaseline: '1–5 scheduled tasks created/day by IT. Multiple mechanisms simultaneously: should be zero.',
  },
};
