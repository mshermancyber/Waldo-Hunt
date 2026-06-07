// Unit test assertions per detection — expected output validation
// "Given these events, expect delete_count > 100, risk_score = CRITICAL"

export interface TestAssertion {
  activity: string;
  env: 'aws' | 'onprem';
  givenDescription: string;
  expectedFields: Record<string, string | number>;
  expectedRowCount: number;
  expectedRiskLevel: string;
}

export const TEST_ASSERTIONS: Record<string, TestAssertion[]> = {
  delete_data: [
    {
      activity: 'delete_data', env: 'aws',
      givenDescription: '500 DeleteObject events from a single user in 1 hour across 3 production buckets',
      expectedFields: { delete_count: '> 100', bucket_count: '3', risk_score: 'HIGH or CRITICAL' },
      expectedRowCount: 1, expectedRiskLevel: 'HIGH',
    },
    {
      activity: 'delete_data', env: 'aws',
      givenDescription: '3 DeleteObject events from a user cleaning up temporary test files',
      expectedFields: { delete_count: '< 100' },
      expectedRowCount: 0, expectedRiskLevel: 'NONE (no alert)',
    },
  ],
  s3_exfil: [
    {
      activity: 's3_exfil', env: 'aws',
      givenDescription: '1000 GetObject calls totaling 15 GB from a single requester',
      expectedFields: { download_count: '> 200', total_gb: '> 10', risk: 'CRITICAL' },
      expectedRowCount: 1, expectedRiskLevel: 'CRITICAL',
    },
    {
      activity: 's3_exfil', env: 'aws',
      givenDescription: '50 GetObject calls totaling 500 MB — within normal baseline',
      expectedFields: { download_count: '< 200' },
      expectedRowCount: 0, expectedRiskLevel: 'NONE (no alert)',
    },
  ],
  priv_escalation: [
    {
      activity: 'priv_escalation', env: 'aws',
      givenDescription: 'AttachUserPolicy with AdministratorAccess + CreateAccessKey in same hour',
      expectedFields: { admin_grants: '>= 1', severity: 'CRITICAL' },
      expectedRowCount: 1, expectedRiskLevel: 'CRITICAL',
    },
    {
      activity: 'priv_escalation', env: 'aws',
      givenDescription: 'Single AddUserToGroup by IAM admin during business hours',
      expectedFields: { admin_grants: '0' },
      expectedRowCount: 0, expectedRiskLevel: 'NONE (no alert — single action, no admin grant)',
    },
  ],
  recon: [
    {
      activity: 'recon', env: 'aws',
      givenDescription: '200 Describe/List API calls across 10 services from a new IP',
      expectedFields: { api_count: '> 50', services_probed: '> 8', risk: 'CRITICAL' },
      expectedRowCount: 1, expectedRiskLevel: 'CRITICAL',
    },
  ],
  credential_harvest: [
    {
      activity: 'credential_harvest', env: 'aws',
      givenDescription: '20 GetSecretValue + 5 GetSessionToken calls from same user in 1 hour',
      expectedFields: { cred_ops: '> 5', op_types: '>= 3', risk: 'HIGH' },
      expectedRowCount: 1, expectedRiskLevel: 'HIGH',
    },
  ],
  lateral_move: [
    {
      activity: 'lateral_move', env: 'aws',
      givenDescription: 'AssumeRole to 5 different accounts outside normal chain',
      expectedFields: { roles_assumed: '>= 3', cross_account_count: '>= 2', risk: 'HIGH or CRITICAL' },
      expectedRowCount: 1, expectedRiskLevel: 'HIGH',
    },
  ],
};

export function getTestForActivity(activity: string, env: 'aws' | 'onprem'): TestAssertion[] {
  return TEST_ASSERTIONS[activity]?.filter(t => t.env === env) || [];
}

// Expected notable event output format samples
export function getExpectedOutputSample(activity: string, env: 'aws' | 'onprem'): string {
  const samples: Record<string, Record<string, string>> = {
    aws: {
      delete_data: `┌─────────────────────────────────────────────────────────┐
│ NOTABLE EVENT — Insider Threat: Mass Data Deletion      │
├─────────────────────────────────────────────────────────┤
│ Severity:        HIGH                                    │
│ Category:        Insider Threat                          │
│ Time:            2026-06-07 03:17:42 UTC                 │
│ User:            arn:aws:iam::123456789012:user/insider  │
│ Risk Score:      70                                      │
│                                                        │
│ delete_count:    547                                     │
│ bucket_count:    3                                       │
│ buckets:         production-data, customer-pii, backups  │
│ risk_score:      HIGH                                    │
│ firstTime:       2026-06-07 02:45:01                    │
│ lastTime:        2026-06-07 03:17:42                    │
│                                                        │
│ MITRE TTPs:      T1485 (Data Destruction)               │
│                  T1490 (Inhibit System Recovery)        │
│                                                        │
│ Drilldown:       search index=aws_cloudtrail ...        │
└─────────────────────────────────────────────────────────┘`,
      priv_escalation: `┌─────────────────────────────────────────────────────────┐
│ NOTABLE EVENT — Insider Threat: Privilege Escalation     │
├─────────────────────────────────────────────────────────┤
│ Severity:        CRITICAL                                │
│ Category:        Insider Threat                          │
│ Time:            2026-06-07 01:23:15 UTC                 │
│ User:            arn:aws:iam::123456789012:user/insider  │
│ Risk Score:      90                                      │
│                                                        │
│ action_types:    3                                       │
│ admin_grants:    1                                       │
│ actions:         AttachUserPolicy, CreateAccessKey,     │
│                  AddUserToGroup                         │
│ severity:        CRITICAL                               │
│                                                        │
│ MITRE TTPs:      T1078 (Valid Accounts)                │
│                  T1098 (Account Manipulation)           │
└─────────────────────────────────────────────────────────┘`,
    },
    onprem: {
      delete_data: `┌─────────────────────────────────────────────────────────┐
│ NOTABLE EVENT — Insider Threat: Mass Data Deletion      │
├─────────────────────────────────────────────────────────┤
│ Severity:        HIGH                                    │
│ Category:        Insider Threat                          │
│ Time:            2026-06-07 14:55:30 UTC                 │
│ User:            INSIDER\\jsmith                          │
│ Risk Score:      70                                      │
│                                                        │
│ delete_count:    312                                     │
│ unique_files:    47                                      │
│ risk:            HIGH                                    │
│                                                        │
│ MITRE TTPs:      T1485 (Data Destruction)               │
└─────────────────────────────────────────────────────────┘`,
    },
  };

  const envSamples = samples[env] || {};
  return envSamples[activity] || `# Expected output for ${activity} (${env})\n# Run the detection SPL against your test data and verify:\n# 1. Row count matches expected threshold\n# 2. Risk level is appropriate\n# 3. All required fields are populated`;
}
