// Datadog Cloud SIEM detection rule templates
// Vendor-native JSON format for Datadog Security Platform

interface DatadogRule {
  name: string;
  type: string;
  query: string;
  message: string;
  tags: string[];
  options: {
    evaluationWindow: number;
    keepAlive: number;
    maxSignalDuration: number;
    severity: string;
    detectionMethod: string;
  };
}

export function generateDatadog(activity: string, title: string, env: 'aws' | 'onprem'): DatadogRule | null {
  if (env === 'aws') return generateAwsDatadog(activity, title);
  return generateOnpremDatadog(activity, title);
}

function generateAwsDatadog(activity: string, title: string): DatadogRule | null {
  const templates: Record<string, DatadogRule> = {
    delete_data: {
      name: `Insider Threat — ${title} (AWS)`,
      type: 'log_detection',
      query: `@evt.name:"DeleteObject" OR @evt.name:"DeleteObjects" OR @evt.name:"DeleteBucket" OR @evt.name:"DeleteItem" OR @evt.name:"DeleteTable" @source:cloudtrail
@usr.name:* -@usr.name:automation -@usr.name:ci-cd
| @usr.name @aws.region count:count() bucket_count:count_distinct(@requestParameters.bucketName) delete_count:count()
| where delete_count > 100
| risk_score:case(when delete_count > 1000 then "CRITICAL", when delete_count > 500 then "HIGH", when delete_count > 100 then "MEDIUM", default "LOW")`,
      message: `Insider Threat: Mass data deletion detected — {{delete_count}} objects deleted by {{@usr.name}} across {{bucket_count}} buckets in {{@aws.region}}.
Risk: {{risk_score}}
See MITRE T1485, T1490.`,
      tags: ['insider-threat', 'cert-cc.sabotage', 'T1485', 'T1490', 'aws', 'cloudtrail'],
      options: { evaluationWindow: 900, keepAlive: 3600, maxSignalDuration: 86400, severity: 'high', detectionMethod: 'threshold' },
    },
    priv_escalation: {
      name: `Insider Threat — ${title} (AWS)`,
      type: 'log_detection',
      query: `@evt.name:(AttachUserPolicy OR AttachRolePolicy OR PutUserPolicy OR PutRolePolicy OR CreateAccessKey) @source:cloudtrail
| @usr.name count:count() admin_grants:sum(if(@requestParameters.policyArn like "AdministratorAccess", 1, 0))
| where admin_grants >= 1 or count >= 2`,
      message: `CRITICAL: IAM privilege escalation — {{@usr.name}} performed {{count}} privilege-related actions including {{admin_grants}} admin grants.
See MITRE T1078.`,
      tags: ['insider-threat', 'cert-cc.fraud', 'T1078', 'T1098', 'aws', 'iam', 'critical'],
      options: { evaluationWindow: 300, keepAlive: 1800, maxSignalDuration: 86400, severity: 'critical', detectionMethod: 'new_value' },
    },
    s3_exfil: {
      name: `Insider Threat — ${title} (AWS)`,
      type: 'log_detection',
      query: `@evt.name:GetObject @source:s3accesslogs @usr.name:*
| @usr.name download_count:count() total_bytes:sum(@bytesSent) unique_files:count_distinct(@key)
| where download_count > 200 OR total_bytes > 1073741824`,
      message: `Data exfiltration: {{@usr.name}} downloaded {{download_count}} objects ({{total_gb}} GB) from S3.
Risk: {{risk}}
See MITRE T1530, T1567.`,
      tags: ['insider-threat', 'cert-cc.ip_theft', 'T1530', 'T1567', 'aws', 's3'],
      options: { evaluationWindow: 3600, keepAlive: 7200, maxSignalDuration: 86400, severity: 'medium', detectionMethod: 'threshold' },
    },
    lateral_move: {
      name: `Insider Threat — ${title} (AWS)`,
      type: 'log_detection',
      query: `@evt.name:AssumeRole @source:cloudtrail
| @usr.name roles_assumed:count_distinct(@requestParameters.roleArn) cross_account:count_distinct(@aws.account.id)
| where roles_assumed >= 3 OR cross_account >= 2`,
      message: `Lateral movement: {{@usr.name}} assumed {{roles_assumed}} roles across {{cross_account}} accounts.
See MITRE T1550.001, T1021.`,
      tags: ['insider-threat', 'cert-cc.espionage', 'T1550.001', 'T1021', 'aws', 'sts'],
      options: { evaluationWindow: 3600, keepAlive: 7200, maxSignalDuration: 86400, severity: 'high', detectionMethod: 'threshold' },
    },
  };
  return templates[activity] || null;
}

function generateOnpremDatadog(activity: string, title: string): DatadogRule | null {
  const templates: Record<string, DatadogRule> = {
    priv_escalation: {
      name: `Insider Threat — ${title} (On-Prem)`,
      type: 'log_detection',
      query: `@evt.id:4728 @source:winsecurity
| @SubjectUserName count:count()
| where count >= 1`,
      message: `CRITICAL: AD privilege escalation — {{@SubjectUserName}} was added to a privileged group.
See MITRE T1078.`,
      tags: ['insider-threat', 'cert-cc.fraud', 'T1078', 'windows', 'active-directory', 'critical'],
      options: { evaluationWindow: 300, keepAlive: 1800, maxSignalDuration: 86400, severity: 'critical', detectionMethod: 'new_value' },
    },
    lateral_move: {
      name: `Insider Threat — ${title} (On-Prem)`,
      type: 'log_detection',
      query: `(@evt.id:4648 OR (@evt.id:4624 AND @LogonType:(3 OR 10))) @source:winsecurity
| @SubjectUserName logon_count:count() unique_systems:count_distinct(@Computer)
| where unique_systems >= 3 AND logon_count > 10`,
      message: `Lateral movement: {{@SubjectUserName}} logged onto {{unique_systems}} systems ({{logon_count}} logons).
See MITRE T1550.001.`,
      tags: ['insider-threat', 'cert-cc.espionage', 'T1550.001', 'T1021', 'windows'],
      options: { evaluationWindow: 3600, keepAlive: 7200, maxSignalDuration: 86400, severity: 'high', detectionMethod: 'threshold' },
    },
  };
  return templates[activity] || null;
}
