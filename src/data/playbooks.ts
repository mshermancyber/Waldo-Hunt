// Response playbooks per detection type
// SOC playbook links, IR team contacts, evidence preservation guidance

export interface Playbook {
  immediateActions: string[];
  investigationSteps: string[];
  containmentActions: string[];
  evidencePreservation: string[];
  escalationCriteria: string;
  contactRole: string;
  sla: string;
}

export const PLAYBOOKS: Record<string, Playbook> = {
  delete_data: {
    immediateActions: [
      'Verify if the deletion was authorized (check change management system)',
      'Identify the IAM user/role that initiated the deletions',
      'Determine the scope: how many objects/buckets/snapshots were affected',
      'Contact the resource owner immediately',
    ],
    investigationSteps: [
      'Pull CloudTrail logs for the userIdentity.arn for the past 72 hours',
      'Check for preceding privilege escalation or credential harvesting events',
      'Review whether the user recently accessed sensitive data (s3_exfil, sensitive_access)',
      'Check if backup/snapshot destruction preceded the mass deletion',
      'Correlate with HR system: is the user pending termination or resignation?',
      'Review IAM policy changes that may have granted the user elevated delete permissions',
    ],
    containmentActions: [
      'Revoke active IAM sessions for the affected user (IAM policy deny + revoke-session)',
      'Enable S3 Object Lock / versioning on affected buckets if not already enabled',
      'Restore deleted objects from versioned buckets or backups',
      'Temporarily restrict DeleteObject permissions to break-glass roles only',
    ],
    evidencePreservation: [
      'Export CloudTrail logs for the incident window to immutable storage (S3 with Object Lock)',
      'Take EBS snapshots of any affected EC2 instances for forensic analysis',
      'Preserve S3 access logs in a separate forensic account',
      'Capture IAM policy state at time of incident (AWS Config snapshot)',
    ],
    escalationCriteria: 'Escalate to IR Lead if: delete_count > 1000, production systems affected, or the user is a privileged admin.',
    contactRole: 'Security Operations Center (SOC) Tier 2',
    sla: '15 minutes',
  },
  s3_exfil: {
    immediateActions: [
      'Identify what data was downloaded: bucket names, object keys, sensitivity levels',
      'Check Macie findings for the affected buckets — any PII/PCI involved?',
      'Determine if the user had legitimate business need to access this data',
      'Note the total volume exfiltrated and timeframe of the activity',
    ],
    investigationSteps: [
      'Pull the full list of downloaded objects from S3 access logs',
      'Classify the sensitivity of each accessed object (PII, PCI, PHI, Trade Secret, etc.)',
      'Check if data was accessed during business hours or off-hours',
      'Correlate with DLP events, USB activity, or email attachment logs',
      'Review whether the user staged data (data_stage) prior to download',
      'Check for cross-account movement after or during the download',
    ],
    containmentActions: [
      'Temporarily revoke S3 read permissions for the user',
      'Enable S3 access logging with real-time streaming if not already configured',
      'Block outbound network traffic from the user\'s IP range',
      'Disable the user\'s active sessions in all AWS accounts',
    ],
    evidencePreservation: [
      'Preserve S3 server access logs for the incident window',
      'Export CloudTrail management events for the user',
      'Capture VPC Flow Logs for the user\'s source IP during the exfiltration window',
    ],
    escalationCriteria: 'Escalate to IR Lead and Legal if: data classified as RESTRICTED, total_gb > 10, or cross-account movement detected.',
    contactRole: 'SOC Tier 2 + Data Protection Officer',
    sla: '15 minutes',
  },
  priv_escalation: {
    immediateActions: [
      'Identify what privileges were granted: admin policies, group memberships, new access keys',
      'Determine if the escalation was self-granted or granted to another user (collusion)',
      'Check if the escalation was followed by destructive or exfiltration actions',
      'Alert the IAM team immediately — this is a critical security event',
    ],
    investigationSteps: [
      'Trace all API calls made after the privilege escalation (CloudTrail event history)',
      'Identify if new access keys or login profiles were created for the target',
      'Check if the escalated role was used to assume roles in other accounts',
      'Review whether similar privilege escalation events have occurred recently',
      'Correlate with unusual login times, source IPs, or MFA changes',
    ],
    containmentActions: [
      'Immediately revoke the escalated privileges',
      'Revoke any access keys created by the user during the incident window',
      'Force password reset and MFA re-enrollment for affected accounts',
      'Create a CloudTrail alarm for the specific escalation patterns observed',
    ],
    evidencePreservation: [
      'Snapshot IAM policies and group memberships before reverting changes',
      'Export complete CloudTrail event history for the user',
      'Preserve AWS Config configuration timeline',
    ],
    escalationCriteria: 'Escalate to IR Lead immediately for any AdminstratorAccess grant. Escalate to CISO if multiple accounts affected.',
    contactRole: 'SOC Tier 2 + IAM Security Team',
    sla: '5 minutes',
  },
  credential_harvest: {
    immediateActions: [
      'Identify which credentials were accessed (secrets, tokens, keys)',
      'Determine if the accessed credentials have been subsequently used',
      'Rotate all credentials that were accessed immediately',
      'Alert the affected service/application owners',
    ],
    investigationSteps: [
      'Check if the accessed credentials were used to access other systems',
      'Review CloudTrail for GetSessionToken/AssumeRole calls using the harvested credentials',
      'Identify if the credential access was followed by lateral movement',
      'Check for similar credential access patterns across other users/services',
    ],
    containmentActions: [
      'Immediately rotate all accessed secrets/credentials',
      'Revoke all active sessions for the affected IAM user',
      'Temporarily restrict Secrets Manager / SSM Parameter Store access',
      'Enable just-in-time access for sensitive credentials',
    ],
    evidencePreservation: [
      'Export the full list of accessed secrets and their access timestamps',
      'Preserve CloudTrail logs for the credential access window',
      'Capture AWS Config snapshots of secret rotation policies',
    ],
    escalationCriteria: 'Escalate to IR Lead and Security Engineering if: production credentials accessed, more than 3 unique secrets accessed.',
    contactRole: 'SOC Tier 2 + Secrets Management Team',
    sla: '10 minutes',
  },
  lateral_move: {
    immediateActions: [
      'Map the chain of assumed roles and accessed accounts',
      'Identify the original source IP and user that initiated the chain',
      'Determine if the movement pattern is consistent with normal job function',
      'Alert the account owners of every account in the chain',
    ],
    investigationSteps: [
      'Trace the full role assumption chain from origin to final destination',
      'Review API calls made in each account after the role was assumed',
      'Check if the lateral movement resulted in data access or resource modifications',
      'Determine if the destination accounts contain sensitive data or production systems',
    ],
    containmentActions: [
      'Revoke cross-account trust relationships used in the attack chain',
      'Revoke all active sessions for the originating IAM principal',
      'Implement SCP to deny cross-account AssumeRole from the originating account',
      'Enable CloudTrail alerts for cross-account AssumeRole events',
    ],
    evidencePreservation: [
      'Export CloudTrail logs from all accounts in the movement chain',
      'Preserve IAM trust policy configurations for forensic review',
      'Capture VPC Flow Logs showing network traffic during the movement',
    ],
    escalationCriteria: 'Escalate if: more than 3 accounts chained, production accounts accessed, or movement originated from outside approved IP range.',
    contactRole: 'SOC Tier 2 + Cloud Security Architecture',
    sla: '15 minutes',
  },
  c2_comms: {
    immediateActions: [
      'Isolate the affected host from the network (network ACL or endpoint isolation)',
      'Identify the destination IPs/domains contacted — check threat intelligence',
      'Determine if the C2 traffic is beaconing (regular intervals, consistent size)',
      'Alert the endpoint detection team',
    ],
    investigationSteps: [
      'Perform memory forensics on the affected endpoint',
      'Check for process injection, scheduled tasks, or registry persistence',
      'Review DNS logs for domain generation algorithm (DGA) patterns',
      'Trace lateral movement from the compromised host to other systems',
    ],
    containmentActions: [
      'Isolate the affected host(s) from the network',
      'Block destination IPs/domains at the firewall/proxy',
      'Revoke any credentials used from the affected host (password reset + MFA re-enroll)',
      'Re-image the affected endpoint after forensic evidence collection',
    ],
    evidencePreservation: [
      'Take full disk image and memory dump of the affected host',
      'Preserve proxy/web gateway logs for the incident window',
      'Capture netflow/packet capture data for the C2 connections',
    ],
    escalationCriteria: 'Escalate to IR Lead and Threat Intelligence if: confirmed malware C2, multiple hosts affected, data exfiltration confirmed.',
    contactRole: 'SOC Tier 2 + Incident Response Team',
    sla: '10 minutes',
  },
  persistence: {
    immediateActions: [
      'Identify all persistence mechanisms created (accounts, tasks, keys, policies)',
      'Determine if the persistence is authorized (scheduled maintenance, new service account)',
      'Check if the same user also performed privilege escalation or credential access',
    ],
    investigationSteps: [
      'Review the full set of IAM resources and scheduled tasks created',
      'Check for backdoor IAM roles with trust policies allowing external accounts',
      'Trace any API calls made from the newly created/existing resources',
      'Look for scheduled tasks with delayed execution (logic bomb pattern)',
    ],
    containmentActions: [
      'Remove unauthorized IAM users, roles, access keys, and scheduled tasks',
      'Revoke all sessions and rotate credentials for affected accounts',
      'Implement SCP to block CreateUser/CreateRole outside approved roles',
      'Enable CloudTrail alerting for persistence-related API calls',
    ],
    evidencePreservation: [
      'Export full IAM configuration (users, roles, policies) at time of detection',
      'Preserve the task/rule definitions before removal',
      'Capture AWS Config timeline for the affected resources',
    ],
    escalationCriteria: 'Escalate if: multiple persistence mechanisms detected, backdoor roles with external trust, or scheduled tasks set for future execution.',
    contactRole: 'SOC Tier 2 + IAM Security Team',
    sla: '15 minutes',
  },
};
