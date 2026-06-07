// Elastic Security EQL (Event Query Language) detection rules
// Vendor-native detection format for Elastic Security / Kibana

interface EQLRule {
  name: string;
  description: string;
  query: string;
  language: string;
  severity: string;
  riskScore: number;
  tags: string[];
}

export function generateEQL(activity: string, title: string, env: 'aws' | 'onprem'): EQLRule | null {
  if (env === 'aws') return generateAwsEQL(activity, title);
  return generateOnpremEQL(activity, title);
}

function generateAwsEQL(activity: string, title: string): EQLRule | null {
  const templates: Record<string, EQLRule> = {
    delete_data: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects mass S3 object deletion in AWS CloudTrail logs. Insider threat IT Sabotage pattern.',
      query: `sequence by user.id with maxspan=24h
[any where event.dataset == "aws.cloudtrail"
  and event.action in ("DeleteObject", "DeleteObjects", "DeleteBucket", "DeleteItem", "DeleteTable")]
[any where event.dataset == "aws.cloudtrail"
  and event.action in ("DeleteObject", "DeleteObjects", "DeleteBucket", "DeleteItem", "DeleteTable")
  and user.id == $0.user.id] with runs=100`,
      language: 'eql',
      severity: 'high',
      riskScore: 73,
      tags: ['insider-threat', 'cert-cc.sabotage', 'T1485', 'T1490'],
    },
    priv_escalation: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects IAM privilege escalation via AdministratorAccess policy attachment.',
      query: `any where event.dataset == "aws.cloudtrail"
  and event.action in ("AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy")
  and (event.action == "AttachUserPolicy" and aws.cloudtrail.request_parameters.policyArn : "*AdministratorAccess*")`,
      language: 'eql',
      severity: 'critical',
      riskScore: 92,
      tags: ['insider-threat', 'cert-cc.fraud', 'T1078', 'T1098'],
    },
    lateral_move: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects cross-account lateral movement via AssumeRole chaining.',
      query: `sequence by user.id with maxspan=4h
[any where event.dataset == "aws.cloudtrail" and event.action == "AssumeRole"]
[any where event.dataset == "aws.cloudtrail" and event.action == "AssumeRole"
  and user.id == $0.user.id
  and aws.cloudtrail.request_parameters.roleArn != $0.aws.cloudtrail.request_parameters.roleArn]`,
      language: 'eql',
      severity: 'high',
      riskScore: 79,
      tags: ['insider-threat', 'cert-cc.espionage', 'T1550.001', 'T1021'],
    },
    s3_exfil: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects bulk S3 object downloads — pattern of high-volume GetObject operations.',
      query: `sequence by user.id with maxspan=1h
[any where event.dataset == "aws.cloudtrail"
  and event.provider == "s3.amazonaws.com"
  and event.action == "GetObject"]
[any where event.dataset == "aws.cloudtrail"
  and event.provider == "s3.amazonaws.com"
  and event.action == "GetObject"
  and user.id == $0.user.id] with runs=200`,
      language: 'eql',
      severity: 'medium',
      riskScore: 65,
      tags: ['insider-threat', 'cert-cc.ip_theft', 'T1530', 'T1567'],
    },
  };
  return templates[activity] || null;
}

function generateOnpremEQL(activity: string, title: string): EQLRule | null {
  const templates: Record<string, EQLRule> = {
    priv_escalation: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects user being added to Domain Admins group (Windows Event 4728).',
      query: `any where event.code == "4728"
  and winlog.event_data.TargetSid : "*-512"
  and not (winlog.event_data.SubjectUserName : "SYSTEM" or winlog.event_data.SubjectUserName : "*$")`,
      language: 'eql',
      severity: 'critical',
      riskScore: 92,
      tags: ['insider-threat', 'cert-cc.fraud', 'T1078', 'T1098'],
    },
    lateral_move: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects lateral movement via explicit credential logons to multiple systems.',
      query: `sequence by user.name with maxspan=4h
[any where event.code == "4648"]
[any where event.code == "4624"
  and winlog.event_data.LogonType in ("3", "10")
  and host.hostname != $0.host.hostname] with runs=3`,
      language: 'eql',
      severity: 'high',
      riskScore: 79,
      tags: ['insider-threat', 'cert-cc.espionage', 'T1550.001', 'T1021'],
    },
    usb_exfil: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects mass file copy to removable media (Event 4663 with USB paths).',
      query: `any where event.code == "4663"
  and winlog.event_data.AccessMask : ("0x10000", "0x40000")
  and not winlog.event_data.ObjectName : ("C:*", "D:*", "*system32*", "*Program Files*")
  and winlog.event_data.ObjectName : "?:*"`,
      language: 'eql',
      severity: 'high',
      riskScore: 78,
      tags: ['insider-threat', 'cert-cc.ip_theft', 'T1052.001'],
    },
    credential_harvest: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects Mimikatz and credential dumping tools via process creation.',
      query: `any where event.category == "process"
  and (process.name : ("mimikatz*", "procdump*", "sekurlsa*")
    or process.command_line : ("*lsass*", "*SAM*", "*ntds.dit*", "*vaultcmd*"))`,
      language: 'eql',
      severity: 'critical',
      riskScore: 95,
      tags: ['insider-threat', 'cert-cc.espionage', 'T1003'],
    },
  };
  return templates[activity] || null;
}
