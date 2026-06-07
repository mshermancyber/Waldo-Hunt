// Lookup CSV generator — produces starter CSV files for the lookup tables
// referenced in WaldoHunt SPL templates

export interface LookupCSVDef {
  name: string;
  filename: string;
  description: string;
  columns: { name: string; type: string; description: string }[];
  exampleRows: string[][];
}

export const LOOKUP_DEFS: LookupCSVDef[] = [
  {
    name: 'sensitive_resources',
    filename: 'sensitive_resources.csv',
    description: 'Maps S3 bucket ARNs to sensitivity levels and data owners. Used by sensitive_access detection.',
    columns: [
      { name: 'resource_arn', type: 'string', description: 'ARN of the S3 bucket or resource' },
      { name: 'sensitivity_level', type: 'string', description: 'One of: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED' },
      { name: 'resource_owner', type: 'string', description: 'Email or team name of the resource owner' },
      { name: 'data_classification', type: 'string', description: 'PII, PCI, PHI, TRADE_SECRET, NONE' },
      { name: 'retention_policy', type: 'string', description: 'Data retention policy reference' },
    ],
    exampleRows: [
      ['arn:aws:s3:::customer-pii-prod', 'RESTRICTED', 'data-protection@corp.com', 'PII', 'RET-7YR'],
      ['arn:aws:s3:::financial-reports', 'CONFIDENTIAL', 'finance-team@corp.com', 'PCI', 'RET-10YR'],
      ['arn:aws:s3:::hr-records', 'RESTRICTED', 'hr@corp.com', 'PII', 'RET-7YR'],
      ['arn:aws:s3:::source-code-repos', 'CONFIDENTIAL', 'engineering@corp.com', 'TRADE_SECRET', 'RET-5YR'],
      ['arn:aws:s3:::public-docs', 'PUBLIC', 'docs-team@corp.com', 'NONE', 'RET-1YR'],
    ],
  },
  {
    name: 'internal_buckets',
    filename: 'internal_buckets.csv',
    description: 'Identifies which S3 buckets are internal/corporate vs. external/personal. Used by data_stage detection.',
    columns: [
      { name: 'bucket', type: 'string', description: 'S3 bucket name' },
      { name: 'is_internal', type: 'boolean', description: 'true if this is a corporate-managed bucket' },
      { name: 'owner_team', type: 'string', description: 'Team responsible for the bucket' },
      { name: 'allowed_external_access', type: 'boolean', description: 'true if external access is explicitly permitted' },
    ],
    exampleRows: [
      ['corp-logs-central', 'true', 'infrastructure', 'false'],
      ['customer-data-prod', 'true', 'data-engineering', 'false'],
      ['personal-backup-jdoe', 'false', 'N/A', 'true'],
      ['external-partner-drop', 'true', 'business-dev', 'true'],
      ['temp-sandbox-playground', 'false', 'N/A', 'true'],
    ],
  },
  {
    name: 'known_corp_domains',
    filename: 'known_corp_domains.csv',
    description: 'List of known corporate domains for filtering proxy/web traffic. Used by cross_account and c2_comms detections.',
    columns: [
      { name: 'domain', type: 'string', description: 'Domain name' },
      { name: 'is_corp', type: 'boolean', description: 'true if this is a corporate domain' },
      { name: 'category', type: 'string', description: 'BUSINESS, CDN, SAAS_APPROVED, SAAS_UNMANAGED, CLOUD_PROVIDER' },
      { name: 'risk_level', type: 'string', description: 'LOW, MEDIUM, HIGH, CRITICAL' },
    ],
    exampleRows: [
      ['corp.com', 'true', 'BUSINESS', 'LOW'],
      ['aws.amazon.com', 'true', 'CLOUD_PROVIDER', 'LOW'],
      ['github.com', 'true', 'SAAS_APPROVED', 'LOW'],
      ['mega.nz', 'false', 'SAAS_UNMANAGED', 'HIGH'],
      ['pastebin.com', 'false', 'SAAS_UNMANAGED', 'MEDIUM'],
      ['dropbox.com', 'false', 'SAAS_UNMANAGED', 'MEDIUM'],
      ['exfil-badactor.xyz', 'false', 'SAAS_UNMANAGED', 'CRITICAL'],
    ],
  },
  {
    name: 'privileged_groups',
    filename: 'privileged_groups.csv',
    description: 'AD groups considered privileged for escalation detection. Used by priv_escalation on-prem detection.',
    columns: [
      { name: 'group_sid', type: 'string', description: 'Security Identifier of the AD group' },
      { name: 'group_name', type: 'string', description: 'Display name' },
      { name: 'privilege_level', type: 'string', description: 'TIER_0, TIER_1, TIER_2' },
      { name: 'requires_breakglass', type: 'boolean', description: 'true if membership requires break-glass approval' },
    ],
    exampleRows: [
      ['S-1-5-21-DOMAIN-512', 'Domain Admins', 'TIER_0', 'true'],
      ['S-1-5-21-DOMAIN-519', 'Enterprise Admins', 'TIER_0', 'true'],
      ['S-1-5-21-DOMAIN-518', 'Schema Admins', 'TIER_0', 'true'],
      ['S-1-5-21-DOMAIN-516', 'Domain Controllers', 'TIER_0', 'true'],
      ['S-1-5-21-DOMAIN-544', 'Administrators', 'TIER_1', 'false'],
    ],
  },
  {
    name: 'sensitive_classifications',
    filename: 'sensitive_classifications.csv',
    description: 'DLP rule classifications for data sensitivity. Used by sensitive_access on-prem detection.',
    columns: [
      { name: 'classification', type: 'string', description: 'DLP rule classification name' },
      { name: 'data_type', type: 'string', description: 'PII, PCI, PHI, SOURCE_CODE, FINANCIAL' },
      { name: 'data_owner', type: 'string', description: 'Team or department that owns this data type' },
      { name: 'alert_on_access', type: 'boolean', description: 'Whether to alert on unauthorized access' },
    ],
    exampleRows: [
      ['PII - SSN', 'PII', 'HR', 'true'],
      ['PII - DOB', 'PII', 'HR', 'true'],
      ['PCI - Credit Card', 'PCI', 'Finance', 'true'],
      ['PHI - Medical Records', 'PHI', 'Legal', 'true'],
      ['Source Code - Proprietary', 'SOURCE_CODE', 'Engineering', 'true'],
      ['Financial - Earnings Reports', 'FINANCIAL', 'Finance', 'true'],
    ],
  },
  {
    name: 'approved_usb_devices',
    filename: 'approved_usb_devices.csv',
    description: 'Whitelist of approved USB device serial numbers. Used by usb_exfil detection.',
    columns: [
      { name: 'device_serial', type: 'string', description: 'USB device serial number' },
      { name: 'assigned_user', type: 'string', description: 'User the device is assigned to' },
      { name: 'device_type', type: 'string', description: 'ENCRYPTED_IRONKEY, ENCRYPTED_BITLOCKER, IT_RECOVERY' },
      { name: 'approved_until', type: 'string', description: 'Approval expiry date (YYYY-MM-DD)' },
    ],
    exampleRows: [
      ['4C530001234567890123', 'it-support@corp.com', 'IT_RECOVERY', '2027-12-31'],
      ['KSD23004567890123', 'ciso@corp.com', 'ENCRYPTED_IRONKEY', '2027-06-30'],
    ],
  },
];

export function generateLookupCSV(defKey: string): string {
  const def = LOOKUP_DEFS.find((d) => d.name === defKey);
  if (!def) return '';
  const header = def.columns.map((c) => c.name).join(',');
  const rows = def.exampleRows.map((r) => r.join(',')).join('\n');
  return `${header}\n${rows}\n`;
}

export function generateAllLookupCSVs(): Record<string, string> {
  const result: Record<string, string> = {};
  LOOKUP_DEFS.forEach((def) => {
    result[def.filename] = generateLookupCSV(def.name);
  });
  return result;
}
