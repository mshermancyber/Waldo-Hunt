// Sigma rule templates — vendor-agnostic YAML detection format
// https://github.com/SigmaHQ/sigma

export interface SigmaRule {
  title: string;
  id: string;
  status: string;
  level: string;
  description: string;
  tags: string[];
  logsource: { category?: string; product?: string; service?: string };
  detection: Record<string, Record<string, string | string[]>>;
}

const sigmaId = (act: string, env: string): string =>
  `waldohunt-${env}-${act}-${Date.now().toString(36)}`;

export function generateSigma(act: string, title: string, env: 'aws' | 'onprem'): SigmaRule | null {
  if (env === 'aws') return generateAwsSigma(act, title);
  return generateOnpremSigma(act, title);
}

function generateAwsSigma(act: string, title: string): SigmaRule | null {
  const rules: Record<string, SigmaRule> = {
    delete_data: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'high',
      description: 'Detects mass deletion of S3 objects, DB snapshots, or files by an insider. Part of the CERT/CC IT Sabotage pattern.',
      tags: ['attack.t1485', 'attack.t1490', 'insider-threat', 'cert-cc.it-sabotage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['DeleteObject', 'DeleteObjects', 'DeleteBucket', 'DeleteItem', 'DeleteTable'],
        },
        condition: { count: 'count by userIdentity.arn > 100' },
      },
    },
    resource_destroy: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'high',
      description: 'Detects termination of compute instances, deletion of functions, VPCs, and infrastructure at scale.',
      tags: ['attack.t1485', 'attack.t1489', 'insider-threat', 'cert-cc.it-sabotage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['TerminateInstances', 'DeleteFunction', 'DeleteVpc', 'DeleteStack', 'DeleteCluster', 'DeleteDBInstance', 'DeleteDomain'],
        },
        condition: { destroy_count: 'count by userIdentity.arn > 5' },
      },
    },
    config_tamper: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'high',
      description: 'Detects modification of security controls, logging, and policy tampering by an insider.',
      tags: ['attack.t1562.001', 'attack.t1562.002', 'insider-threat', 'cert-cc.it-sabotage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutBucketPolicy', 'DeleteBucketPolicy', 'AuthorizeSecurityGroupIngress', 'DisableEbsEncryptionByDefault', 'ModifyInstanceAttribute'],
        },
        condition: { count: 'count by userIdentity.arn > 2' },
      },
    },
    s3_exfil: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'medium',
      description: 'Detects bulk download of S3 objects exceeding normal thresholds — insider data exfiltration.',
      tags: ['attack.t1530', 'attack.t1567', 'insider-threat', 'cert-cc.ip-theft'],
      logsource: { product: 'aws', service: 's3access' },
      detection: {
        selection: {
          operation: ['REST.GET.OBJECT', 'REST.COPY.OBJECT_GET', 'REST.HEAD.OBJECT'],
        },
        condition: { download_count: 'count by requester > 200' },
      },
    },
    repo_clone: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'medium',
      description: 'Detects bulk cloning or downloading of source code repositories.',
      tags: ['attack.t1213', 'attack.t1530', 'insider-threat', 'cert-cc.ip-theft'],
      logsource: { product: 'aws', service: 'codecommit' },
      detection: {
        selection: {
          eventName: ['GitPull', 'GitClone', 'GetRepository', 'BatchGetRepositories'],
        },
        condition: { repos_accessed: 'dc(repository) by userIdentity.arn >= 3' },
      },
    },
    priv_escalation: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'critical',
      description: 'Detects attachment of admin policies, creation of access keys, or role assumption for privilege escalation.',
      tags: ['attack.t1078', 'attack.t1098', 'insider-threat', 'cert-cc.fraud'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy', 'CreateAccessKey', 'AddUserToGroup', 'UpdateAssumeRolePolicy', 'CreateRole', 'CreateUser'],
        },
        condition: { admin_grants: 'sum of admin policy attachments >= 1' },
      },
    },
    recon: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'medium',
      description: 'Detects broad Describe/List API reconnaissance across multiple AWS services.',
      tags: ['attack.t1580', 'attack.t1087', 'attack.t1526', 'insider-threat', 'cert-cc.espionage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['DescribeInstances', 'ListBuckets', 'DescribeVpcs', 'ListFunctions', 'DescribeDBInstances', 'ListRoles', 'ListUsers', 'DescribeSecurityGroups'],
        },
        condition: { api_count: 'count by userIdentity.arn > 50' },
      },
    },
    credential_harvest: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'high',
      description: 'Detects unusual access to IAM credentials, tokens, and secrets for exfiltration.',
      tags: ['attack.t1003', 'attack.t1528', 'insider-threat', 'cert-cc.espionage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: {
          eventName: ['GetSessionToken', 'AssumeRoleWithWebIdentity', 'GetFederationToken', 'CreateAccessKey', 'ListAccessKeys', 'GetAccessKeyLastUsed'],
        },
        condition: { cred_ops: 'count by userIdentity.arn > 5' },
      },
    },
    lateral_move: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'aws'),
      status: 'experimental',
      level: 'medium',
      description: 'Detects role chaining and cross-account assumption for lateral movement.',
      tags: ['attack.t1550.001', 'attack.t1021', 'insider-threat', 'cert-cc.espionage'],
      logsource: { product: 'aws', service: 'cloudtrail' },
      detection: {
        selection: { eventName: 'AssumeRole' },
        condition: { roles_assumed: 'dc(assumed_role) by caller_arn >= 3' },
      },
    },
  };

  return rules[act] || null;
}

function generateOnpremSigma(act: string, title: string): SigmaRule | null {
  const rules: Record<string, SigmaRule> = {
    delete_data: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'onprem'),
      status: 'experimental',
      level: 'high',
      description: 'Detects mass file deletion via Windows Event Log 4663 with DELETE access masks.',
      tags: ['attack.t1485', 'insider-threat', 'cert-cc.it-sabotage'],
      logsource: { product: 'windows', service: 'security' },
      detection: {
        selection: { EventID: '4663', AccessMask: ['0x10000', '0x40000'] },
        condition: { delete_count: 'count by SubjectUserName > 50' },
      },
    },
    usb_exfil: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'onprem'),
      status: 'experimental',
      level: 'high',
      description: 'Detects data exfiltration to USB removable media via Windows Event 4663 and CrowdStrike RemovableMedia events.',
      tags: ['attack.t1052.001', 'insider-threat', 'cert-cc.ip-theft'],
      logsource: { product: 'windows', service: 'security' },
      detection: {
        selection: { EventID: ['4663', '6416'] },
        removable: { ObjectName_Matches: '(?i)\\\\[A-Z]:\\\\' },
        condition: { file_count: 'count by SubjectUserName > 20' },
      },
    },
    priv_escalation: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'onprem'),
      status: 'experimental',
      level: 'critical',
      description: 'Detects addition to privileged AD groups (Domain Admins, Enterprise Admins, Schema Admins).',
      tags: ['attack.t1078', 'attack.t1098', 'insider-threat', 'cert-cc.fraud'],
      logsource: { product: 'windows', service: 'security' },
      detection: {
        selection: { EventID: ['4728', '4732', '4756'] },
        condition: { count: 'count by SubjectUserName >= 1' },
      },
    },
    credential_harvest: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'onprem'),
      status: 'experimental',
      level: 'critical',
      description: 'Detects Mimikatz, procdump, and LSASS dumping via CrowdStrike process events.',
      tags: ['attack.t1003', 'insider-threat', 'cert-cc.espionage'],
      logsource: { product: 'edr', service: 'crowdstrike' },
      detection: {
        selection: {
          ImageFileName_contains: ['mimikatz', 'procdump', 'sekurlsa'],
          CommandLine_contains: ['lsass', 'SAM', 'ntds.dit', 'vaultcmd'],
        },
        condition: { proc_count: 'count by UserName >= 1' },
      },
    },
    lateral_move: {
      title: `Insider Threat — ${title}`,
      id: sigmaId(act, 'onprem'),
      status: 'experimental',
      level: 'medium',
      description: 'Detects lateral movement via explicit credentials (Event 4648) and network logons (4624 type 3/10) across multiple systems.',
      tags: ['attack.t1550.001', 'attack.t1021', 'insider-threat', 'cert-cc.espionage'],
      logsource: { product: 'windows', service: 'security' },
      detection: {
        selection: { EventID: ['4648', '4624'], LogonType: ['3', '10'] },
        condition: { unique_systems: 'dc(Computer) by SubjectUserName >= 3' },
      },
    },
  };

  return rules[act] || null;
}
