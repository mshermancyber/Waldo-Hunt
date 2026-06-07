// KQL templates for Microsoft Sentinel / Defender 365
// Generates equivalent Kusto Query Language for insider threat detections

interface KQLTemplate {
  title: string;
  query: string;
  requiredTables: string[];
  mitreTactics: string[];
}

export function generateKQL(act: string, title: string, env: 'aws' | 'onprem'): KQLTemplate | null {
  if (env === 'aws') return generateAwsKQL(act, title);
  return generateOnpremKQL(act, title);
}

function generateAwsKQL(act: string, title: string): KQLTemplate | null {
  const templates: Record<string, KQLTemplate> = {
    delete_data: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventName in~ ("DeleteObject","DeleteObjects","DeleteBucket","DeleteItem","DeleteTable")
| summarize DeleteCount=count(),
    BucketCount=dcount(tostring(parse_json(RequestParameters).bucketName)),
    FirstTime=min(TimeGenerated), LastTime=max(TimeGenerated)
    by UserIdentityArn=tostring(parse_json(UserIdentity).arn), AwsRegion
| where DeleteCount > 100
| extend RiskScore=case(DeleteCount > 1000, "CRITICAL", DeleteCount > 500, "HIGH", DeleteCount > 100, "MEDIUM", "LOW")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Impact'],
    },
    s3_exfil: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventSource == "s3.amazonaws.com"
| where EventName in~ ("GetObject","HeadObject")
| summarize DownloadCount=count(),
    TotalBytes=sum(tolong(tostring(parse_json(AdditionalEventData).bytessent))),
    UniqueFiles=dcount(tostring(parse_json(RequestParameters).key)),
    BucketCount=dcount(tostring(parse_json(RequestParameters).bucketName))
    by Requester=tostring(parse_json(UserIdentity).arn)
| where DownloadCount > 200 or TotalBytes > 1073741824
| extend TotalGB=round(TotalBytes/1073741824.0, 2)
| extend Risk=case(TotalGB > 10, "CRITICAL", DownloadCount > 1000, "HIGH", DownloadCount > 200, "MEDIUM", "LOW")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Exfiltration', 'Collection'],
    },
    priv_escalation: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventName in~ ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","CreateAccessKey","AddUserToGroup","CreateRole","CreateUser")
| extend IsAdminGrant=iff(EventName has_any ("AdministratorAccess") or tostring(parse_json(RequestParameters).policyDocument) contains "*", 1, 0)
| summarize Count=count(), ActionTypes=dcount(EventName), AdminGrants=sum(IsAdminGrant)
    by UserIdentityArn=tostring(parse_json(UserIdentity).arn), TargetUser=tostring(parse_json(RequestParameters).userName)
| where Count >= 2 or AdminGrants >= 1
| extend Severity=case(AdminGrants >= 1, "CRITICAL", Count >= 5, "HIGH", "MEDIUM")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Privilege Escalation', 'Persistence'],
    },
    recon: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventName matches regex "Describe|List[A-Z]|Get[A-Z].*"
| where EventName !in~ ("GetObject","GetSecretValue","GetParameter")
| summarize ApiCount=count(), UniqueApis=dcount(EventName), ServicesProbed=dcount(EventSource)
    by UserIdentityArn=tostring(parse_json(UserIdentity).arn), SourceIP=SourceIpAddress
| where ApiCount > 50 and UniqueApis >= 5
| extend Risk=case(ServicesProbed > 8, "CRITICAL", ServicesProbed > 5, "HIGH", UniqueApis > 10, "MEDIUM", "LOW")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Discovery'],
    },
    cross_account: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventName == "AssumeRole"
| extend TargetAccount=extract("arn:aws:iam::(\\\\d{12})", 1, tostring(parse_json(RequestParameters).roleArn))
| where TargetAccount != AwsAccountId
| summarize Count=count(), UniqueAccounts=dcount(TargetAccount)
    by UserIdentityArn=tostring(parse_json(UserIdentity).arn), SourceIP=SourceIpAddress
| where UniqueAccounts >= 2 or Count > 10
| extend Risk=case(UniqueAccounts > 5, "CRITICAL", UniqueAccounts > 2, "HIGH", "MEDIUM")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Lateral Movement', 'Defense Evasion'],
    },
    persistence: {
      title: `Insider Threat — ${title} (AWS)`,
      query: `AWSCloudTrail
| where EventName in~ ("CreateUser","CreateAccessKey","CreateLoginProfile","PutUserPolicy","AttachUserPolicy","CreateRole","UpdateAssumeRolePolicy","CreateSchedule","PutRule","PutTargets")
| extend PersistType=case(
    EventName in~ ("CreateUser","CreateLoginProfile","CreateAccessKey"), "New Identity",
    EventName in~ ("PutUserPolicy","AttachUserPolicy","UpdateAssumeRolePolicy"), "Policy Backdoor",
    EventName in~ ("CreateSchedule","PutRule","PutTargets"), "Scheduled Persistence",
    "Other")
| summarize Count=count(), MechanismCount=dcount(PersistType)
    by UserIdentityArn=tostring(parse_json(UserIdentity).arn), SourceIP=SourceIpAddress
| where Count >= 2 or MechanismCount >= 2
| extend Risk=case(MechanismCount >= 3, "CRITICAL", MechanismCount >= 2, "HIGH", "MEDIUM")`,
      requiredTables: ['AWSCloudTrail'],
      mitreTactics: ['Persistence', 'Execution'],
    },
  };

  return templates[act] || null;
}

function generateOnpremKQL(act: string, title: string): KQLTemplate | null {
  const templates: Record<string, KQLTemplate> = {
    delete_data: {
      title: `Insider Threat — ${title} (On-Prem)`,
      query: `SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in~ ("0x10000", "0x40000")
| summarize DeleteCount=count(), UniqueFiles=dcount(ObjectName)
    by SubjectUserName, SubjectDomainName, IpAddress
| where DeleteCount > 50
| extend Risk=case(DeleteCount > 500, "CRITICAL", DeleteCount > 100, "HIGH", "MEDIUM")`,
      requiredTables: ['SecurityEvent'],
      mitreTactics: ['Impact'],
    },
    usb_exfil: {
      title: `Insider Threat — ${title} (On-Prem)`,
      query: `union
(SecurityEvent
| where EventID in~ (4663, 6416)
| where ObjectName matches regex "[D-Z]:\\\\\\\\.*"
| where ObjectName !startswith "C:\\\\" and ObjectName !startswith "D:\\\\"
| summarize FileCount=count(), UniqueFiles=dcount(ObjectName) by SubjectUserName, Computer),
(DeviceEvents
| where ActionType == "RemovableMediaCreated"
| summarize UsbEvents=count(), Devices=dcount(DeviceId) by InitiatingProcessAccountUpn, DeviceName
| where UsbEvents > 10)
| extend Risk=case(FileCount > 100, "HIGH", "MEDIUM")`,
      requiredTables: ['SecurityEvent', 'DeviceEvents'],
      mitreTactics: ['Exfiltration'],
    },
    priv_escalation: {
      title: `Insider Threat — ${title} (On-Prem)`,
      query: `SecurityEvent
| where EventID in~ (4728, 4732, 4756)
| extend EscalationType=case(
    EventID == 4728, "Added to Global Group",
    EventID == 4732, "Added to Domain Local Group",
    EventID == 4756, "Added to Universal Group",
    "Other")
| summarize Count=count(), TypeCount=dcount(EscalationType)
    by SubjectUserName, SubjectDomainName, TargetUserName
| where Count >= 1
| extend Severity=case(TypeCount >= 2, "CRITICAL", "HIGH")`,
      requiredTables: ['SecurityEvent'],
      mitreTactics: ['Privilege Escalation', 'Persistence'],
    },
    lateral_move: {
      title: `Insider Threat — ${title} (On-Prem)`,
      query: `SecurityEvent
| where EventID in~ (4648, 4624)
| where LogonType in~ (3, 10)
| summarize LogonCount=count(), UniqueSystems=dcount(Computer)
    by SubjectUserName, SubjectDomainName, IpAddress
| where UniqueSystems >= 3 and LogonCount > 10
| extend Risk=case(UniqueSystems > 10, "CRITICAL", UniqueSystems > 5, "HIGH", "MEDIUM")`,
      requiredTables: ['SecurityEvent'],
      mitreTactics: ['Lateral Movement'],
    },
    credential_harvest: {
      title: `Insider Threat — ${title} (On-Prem)`,
      query: `DeviceProcessEvents
| where FileName has_any ("mimikatz", "procdump", "sekurlsa")
    or ProcessCommandLine has_any ("lsass", "SAM", "ntds.dit", "vaultcmd")
| summarize ProcCount=count(), ToolsUsed=make_set(FileName)
    by AccountUpn, DeviceName
| extend Severity=case(
    array_strcat(ToolsUsed, " ") contains "mimikatz", "CRITICAL",
    "HIGH")`,
      requiredTables: ['DeviceProcessEvents'],
      mitreTactics: ['Credential Access'],
    },
  };

  return templates[act] || null;
}
