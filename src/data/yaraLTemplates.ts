// Google SecOps (Chronicle) YARA-L 2.0 detection rules
// Vendor-native detection format for Google Chronicle SIEM

interface YARALRule {
  name: string;
  description: string;
  events: string;
  match: string;
  outcome: string;
}

export function generateYARAL(activity: string, title: string, env: 'aws' | 'onprem'): YARALRule | null {
  if (env === 'aws') return generateAwsYARAL(activity, title);
  return generateOnpremYARAL(activity, title);
}

function generateAwsYARAL(activity: string, title: string): YARALRule | null {
  const templates: Record<string, YARALRule> = {
    delete_data: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects mass S3 object deletion indicative of insider IT sabotage. Part of CERT/CC pattern.',
      events: `$cloudtrail.metadata.event_type = "GENERIC_EVENT"
$cloudtrail.metadata.product_name = "CloudTrail"
$cloudtrail.metadata.vendor_name = "AWS"
$cloudtrail.target.process.name = /DeleteObject|DeleteObjects|DeleteBucket|DeleteItem|DeleteTable/
match:
  $cloudtrail`,
      match: `$user = $cloudtrail.principal.user.userid
$region = $cloudtrail.target.resource.region
$event_types = array_distinct($cloudtrail.target.process.name)`,
      outcome: `$delete_count = count($cloudtrail.metadata.id)
$bucket_count = count_distinct($cloudtrail.target.resource.name)
$risk_score = max(
  if($delete_count > 1000, "CRITICAL",
  if($delete_count > 500, "HIGH",
  if($delete_count > 100, "MEDIUM", "LOW")))
)`,
    },
    priv_escalation: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects privilege escalation via IAM policy attachment with AdministratorAccess.',
      events: `$cloudtrail.metadata.event_type = "GENERIC_EVENT"
$cloudtrail.metadata.product_name = "CloudTrail"
$cloudtrail.target.process.name = /AttachUserPolicy|AttachRolePolicy|PutRolePolicy|CreateAccessKey|AddUserToGroup/
match:
  $cloudtrail`,
      match: `$user = $cloudtrail.principal.user.userid
$is_admin = if($cloudtrail.target.resource.name = /AdministratorAccess/, 1, 0)`,
      outcome: `$action_count = count($cloudtrail.metadata.id)
$admin_grants = sum($is_admin)
$severity = if($admin_grants >= 1, "CRITICAL", if($action_count >= 5, "HIGH", "MEDIUM"))`,
    },
    s3_exfil: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects bulk S3 object downloads exceeding 200 objects or 10 GB.',
      events: `$s3.metadata.event_type = "GENERIC_EVENT"
$s3.metadata.product_name = "S3"
$s3.target.process.name = /GetObject/
match:
  $s3`,
      match: `$requester = $s3.principal.user.userid`,
      outcome: `$download_count = count($s3.metadata.id)
$total_bytes = sum($s3.network.sent_bytes)
$total_gb = $total_bytes / 1073741824
$risk = if($total_gb > 10, "CRITICAL", if($download_count > 1000, "HIGH", if($download_count > 200, "MEDIUM", "LOW")))`,
    },
    lateral_move: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects cross-account lateral movement via AssumeRole chaining.',
      events: `$cloudtrail.metadata.event_type = "GENERIC_EVENT"
$cloudtrail.metadata.product_name = "CloudTrail"
$cloudtrail.target.process.name = "AssumeRole"
match:
  $cloudtrail`,
      match: `$caller = $cloudtrail.principal.user.userid
$target_account = re.capture($cloudtrail.target.resource.name, "arn:aws:iam::(\\d{12})")`,
      outcome: `$roles_assumed = count_distinct($cloudtrail.target.resource.name)
$cross_account_count = count_distinct($target_account)
$risk = if($cross_account_count > 5, "CRITICAL", if($cross_account_count > 2, "HIGH", "MEDIUM"))`,
    },
    credential_harvest: {
      name: `Insider Threat — ${title} (AWS)`,
      description: 'Detects mass credential and secrets access via Secrets Manager and IAM.',
      events: `$cloudtrail.metadata.event_type = "GENERIC_EVENT"
$cloudtrail.metadata.product_name = "CloudTrail"
$cloudtrail.target.process.name = /GetSecretValue|GetSessionToken|CreateAccessKey|ListAccessKeys/
match:
  $cloudtrail`,
      match: `$user = $cloudtrail.principal.user.userid
$operation_types = array_distinct($cloudtrail.target.process.name)`,
      outcome: `$cred_ops = count($cloudtrail.metadata.id)
$op_types = count_distinct($cloudtrail.target.process.name)
$risk = if($cred_ops > 20, "HIGH", "MEDIUM")`,
    },
  };
  return templates[activity] || null;
}

function generateOnpremYARAL(activity: string, title: string): YARALRule | null {
  const templates: Record<string, YARALRule> = {
    priv_escalation: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects user added to privileged AD group (Event 4728).',
      events: `$win.metadata.event_type = "GENERIC_EVENT"
$win.metadata.product_name = "Windows"
$win.metadata.event_id = 4728
match:
  $win`,
      match: `$user = $win.principal.user.userid
$target = $win.target.user.userid`,
      outcome: `$count = count($win.metadata.id)
$severity = if($count > 2, "CRITICAL", "HIGH")`,
    },
    lateral_move: {
      name: `Insider Threat — ${title} (On-Prem)`,
      description: 'Detects lateral movement via explicit credentials (Event 4648) and network logons (4624) across multiple systems.',
      events: `$win.metadata.event_type = "GENERIC_EVENT"
$win.metadata.product_name = "Windows"
$win.metadata.event_id = /4648|4624/
$win.target.process.name = /3|10/
match:
  $win`,
      match: `$user = $win.principal.user.userid
$computers = array_distinct($win.principal.hostname)`,
      outcome: `$logon_count = count($win.metadata.id)
$unique_systems = count_distinct($win.principal.hostname)
$risk = if($unique_systems > 10, "CRITICAL", if($unique_systems > 5, "HIGH", "MEDIUM"))`,
    },
  };
  return templates[activity] || null;
}
