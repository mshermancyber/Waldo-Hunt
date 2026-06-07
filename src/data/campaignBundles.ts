// Campaign-based detection bundles — curated sets for known insider threat campaigns

export interface CampaignBundle {
  id: string;
  name: string;
  description: string;
  basedOn: string;
  recommendedPatterns: string[];
  recommendedActivities: string[];
  narrative: string;
  timeline: string[];
  indicators: string[];
}

export const CAMPAIGN_BUNDLES: CampaignBundle[] = [
  {
    id: 'solarwinds-insider',
    name: 'SolarWinds-Style Insider Compromise',
    description: 'Detections for a compromised privileged insider scenario based on the 2020 SolarWinds campaign. An attacker with legitimate access abuses credentials for lateral movement, data collection, and C2.',
    basedOn: 'APT29 / SolarWinds 2020',
    recommendedPatterns: ['espionage', 'ip_theft'],
    recommendedActivities: ['credential_harvest', 'lateral_move', 'persistence', 'sensitive_access', 'c2_comms', 'recon'],
    narrative: 'A software engineer\'s credentials are compromised via a supply chain attack. The attacker uses the engineer\'s legitimate access to harvest additional credentials, move laterally across AWS accounts, access sensitive data repositories, establish persistence through new IAM roles, and exfiltrate data through C2 channels over HTTPS.',
    timeline: [
      'Day 1-7: Initial access via compromised build pipeline — attacker gains engineer\'s AWS credentials',
      'Day 8-14: Reconnaissance — broad Describe/List API calls across 12 AWS services',
      'Day 15-21: Credential harvesting — GetSecretValue calls on 8+ secrets, AssumeRole across 3 accounts',
      'Day 22-30: Data staging and exfiltration — bulk S3 downloads, cross-account movement, C2 beaconing',
      'Day 30+: Persistence — new IAM roles created, scheduled Lambda functions for continued access',
    ],
    indicators: [
      'First-time AssumeRole to production accounts from development account',
      'GetSecretValue calls at 3 AM local time (off-hours)',
      'New IAM roles with trust policies allowing external accounts',
      'S3 GetObject volume 20× user\'s 30-day baseline',
      'Outbound HTTPS connections to domains with < 30 days age',
    ],
  },
  {
    id: 'departing-employee',
    name: 'Departing Employee Data Theft',
    description: 'Classic insider threat: an employee planning to leave (or recently notified of termination) exfiltrates proprietary data, source code, and customer lists.',
    basedOn: 'CERT/CC IP Theft Pattern',
    recommendedPatterns: ['ip_theft'],
    recommendedActivities: ['s3_exfil', 'repo_clone', 'usb_exfil', 'data_stage', 'secrets_access'],
    narrative: 'A senior engineer gives two weeks\' notice. In their final week, they clone all accessible code repositories, download customer data from S3, copy files to a personal USB drive, and access credential vaults to obtain long-lived API keys.',
    timeline: [
      'T-14 days: Resignation submitted',
      'T-10 days: Unusual repo clone activity — 15 repos in 1 hour (normal: 1-2/week)',
      'T-5 days: S3 exfiltration begins — downloads 50 GB from customer-data bucket',
      'T-3 days: USB device connected for first time, 200+ files copied',
      'T-1 day: Accesses AWS Secrets Manager — obtains production API keys',
    ],
    indicators: [
      'Bulk repo cloning outside normal cadence',
      'S3 download volume spike > 10× baseline',
      'First-time USB mass storage connection',
      'Access to secrets/credentials the user has never accessed before',
      'All activity between 6 PM and 4 AM (off-hours)',
    ],
  },
  {
    id: 'disgruntled-admin',
    name: 'Disgruntled Administrator Sabotage',
    description: 'A system administrator with elevated privileges, facing termination or demotion, executes a destructive campaign — mass deletion, backup destruction, and access revocation.',
    basedOn: 'CERT/CC IT Sabotage Pattern',
    recommendedPatterns: ['sabotage'],
    recommendedActivities: ['delete_data', 'resource_destroy', 'backup_destroy', 'config_tamper', 'access_revoke', 'log_tamper'],
    narrative: 'A cloud administrator is notified of impending layoff. Over the next 48 hours, they delete production S3 buckets, terminate EC2 instances, destroy RDS snapshots and backups, disable CloudTrail logging, revoke other admins\' access, and modify security groups to block all inbound traffic.',
    timeline: [
      'T-48 hours: CloudTrail logging disabled (StopLogging API call)',
      'T-36 hours: Other admin accounts\' access keys deleted',
      'T-24 hours: S3 bucket policies modified to deny all access',
      'T-12 hours: RDS and EBS snapshots deleted — 47 snapshots in 30 minutes',
      'T-2 hours: Mass EC2 termination — 200+ instances in production VPCs',
    ],
    indicators: [
      'StopLogging or DeleteTrail — immediate CRITICAL alert',
      'Deletion of other admins\' access keys or IAM users',
      'Bulk snapshot deletion (> 10 in 1 hour)',
      'Security group modifications during off-hours',
      'Sequence: logging disabled → access revoked → resources destroyed',
    ],
  },
  {
    id: 'credential-harvest-chain',
    name: 'Credential Harvesting Chain for Lateral Movement',
    description: 'An attacker (or malicious insider) harvests credentials from multiple sources, then uses them in a chain of role assumptions to reach high-value targets.',
    basedOn: 'APT28 / APT41 TTP overlap',
    recommendedPatterns: ['espionage', 'fraud'],
    recommendedActivities: ['credential_harvest', 'priv_escalation', 'lateral_move', 'persistence', 'recon'],
    narrative: 'An attacker compromises a developer\'s workstation. Using the developer\'s credentials, they enumerate the AWS environment, harvest additional credentials from Secrets Manager and SSM Parameter Store, escalate privileges by attaching admin policies, then chain AssumeRole calls across 4 accounts to reach the production billing system.',
    timeline: [
      'Day 1: Initial compromise — developer workstation malware delivers Mimikatz',
      'Day 1-2: Credential harvesting — Secrets Manager and SSM accessed, 12 secrets retrieved',
      'Day 2: Privilege escalation — IAM admin policy attached to developer role',
      'Day 2-3: Lateral movement — AssumeRole chain: dev → staging → prod → billing',
      'Day 3+: Persistence — new IAM user created in billing account, access key exfiltrated',
    ],
    indicators: [
      'GetSecretValue + GetSessionToken from same principal within 5 minutes',
      'IAM policy attachment containing "AdministratorAccess" from non-IAM-admin role',
      'AssumeRole chain depth > 2 hops',
      'First-ever AssumeRole to billing/finance accounts',
      'New IAM user created from an assumed role session',
    ],
  },
  {
    id: 'fraud-billing-manipulation',
    name: 'Insider Financial Fraud & Billing Manipulation',
    description: 'An insider with access to financial systems manipulates billing, creates unauthorized resources for personal use, and covers their tracks.',
    basedOn: 'CERT/CC Fraud Pattern',
    recommendedPatterns: ['fraud'],
    recommendedActivities: ['financial_manip', 'resource_abuse', 'account_create', 'log_tamper', 'policy_bypass'],
    narrative: 'A finance operations analyst uses their AWS access to spin up cryptocurrency mining instances, modify reserved instance allocations for personal gain, create shadow billing accounts, disable cost allocation tags, and delete CloudTrail logs to hide activity.',
    timeline: [
      'Week 1: Unauthorized EC2 instances launched in unused regions (crypto mining)',
      'Week 2: Reserved Instance modifications redirect savings to personal account',
      'Week 3: New IAM user created with billing access, cost allocation tags deleted',
      'Week 4: CloudTrail logs tampered — retention shortened, log groups deleted',
    ],
    indicators: [
      'GPU instance types launched in regions never used before',
      'ModifyReservedInstances by non-finance role',
      'DeleteCostAllocationTag followed by CreateBillingGroup',
      'Log retention policy changed immediately after suspicious billing activity',
    ],
  },
];

export function getRelevantBundles(selectedPatterns: string[], selectedActivities: string[]): CampaignBundle[] {
  return CAMPAIGN_BUNDLES.filter((bundle) => {
    const patternMatch = bundle.recommendedPatterns.some((p) => selectedPatterns.includes(p));
    const activityMatch = bundle.recommendedActivities.some((a) => selectedActivities.includes(a));
    return patternMatch || activityMatch;
  });
}

export function getBundleCoveragePercent(bundle: CampaignBundle, selectedActivities: string[]): number {
  if (bundle.recommendedActivities.length === 0) return 0;
  const covered = bundle.recommendedActivities.filter((a) => selectedActivities.includes(a));
  return Math.round((covered.length / bundle.recommendedActivities.length) * 100);
}
