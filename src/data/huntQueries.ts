// Ad-hoc hunt queries — supplemental pivot SPL for when a detection fires
// "If s3_exfil fires, also run this hunt to find what else that user touched."

export interface HuntQuery {
  trigger: string;
  query: string;
  description: string;
  fields: string[];
  visualization: string;
}

export const HUNT_QUERIES: Record<string, HuntQuery[]> = {
  s3_exfil: [
    {
      trigger: 's3_exfil fired — show what else this user downloaded recently',
      query: `index=aws_s3_accesslogs requester=$requester$
| timechart span=1h count by bucket
| rename count as "Downloads per Bucket"`,
      description: 'Timeline of all S3 downloads by this requester across all buckets. Shows download pattern and escalation.',
      fields: ['_time', 'bucket', 'count'],
      visualization: 'Stacked area chart — time on X, download count on Y, color by bucket.',
    },
    {
      trigger: 's3_exfil fired — check what was downloaded and its sensitivity',
      query: `index=aws_s3_accesslogs requester=$requester$
| lookup sensitive_resources resource_arn AS bucket OUTPUT sensitivity_level resource_owner
| stats count by key bucket sensitivity_level
| sort - count
| table key bucket sensitivity_level count`,
      description: 'Shows which specific objects were downloaded and their sensitivity classification. Pivot to identify PII/PCI exposure.',
      fields: ['key', 'bucket', 'sensitivity_level', 'count'],
      visualization: 'Table sorted by count descending with sensitivity level color-coding.',
    },
    {
      trigger: 's3_exfil fired — check for data staging prior to download',
      query: `index=aws_cloudtrail userIdentity.arn=$requester$
eventName IN ("CopyObject","CreateMultipartUpload","PutObject")
| timechart span=1h count`,
      description: 'Shows whether the user staged data (copied to intermediate buckets) before exfiltration.',
      fields: ['_time', 'count'],
      visualization: 'Timechart with overlaid download timeline.',
    },
  ],
  priv_escalation: [
    {
      trigger: 'priv_escalation fired — trace all subsequent actions',
      query: `index=aws_cloudtrail userIdentity.arn=$userIdentity.arn$
_time >= $firstTime$
| timechart span=5m count by eventName`,
      description: 'Every API call made by this user after the privilege escalation. Look for AssumeRole, GetSecretValue, or destructive actions.',
      fields: ['_time', 'eventName', 'count'],
      visualization: 'Heatmap — time on X, API call type on Y, count as color intensity.',
    },
    {
      trigger: 'priv_escalation fired — check for access keys created',
      query: `index=aws_cloudtrail userIdentity.arn=$userIdentity.arn$
eventName=CreateAccessKey
| table eventTime sourceIPAddress userAgent requestParameters.userName`,
      description: 'Lists access keys created by this user. If combined with escalation, these keys may be backdoors.',
      fields: ['eventTime', 'sourceIPAddress', 'userAgent', 'requestParameters.userName'],
      visualization: 'Table — each row is a potentially-backdoored access key.',
    },
    {
      trigger: 'priv_escalation fired — check group membership changes',
      query: `index=aws_cloudtrail userIdentity.arn=$userIdentity.arn$
eventName IN ("AddUserToGroup","AttachGroupPolicy")
| table eventTime eventName requestParameters.groupName requestParameters.policyArn`,
      description: 'Shows group membership changes and policy attachments made during the escalation window.',
      fields: ['eventTime', 'eventName', 'requestParameters.groupName', 'requestParameters.policyArn'],
      visualization: 'Timeline table.',
    },
  ],
  lateral_move: [
    {
      trigger: 'lateral_move fired — map full role assumption chain',
      query: `index=aws_cloudtrail eventName=AssumeRole
| where userIdentity.arn IN ($caller_arn$, $assumed_role$) OR
        requestParameters.roleArn IN ($assumed_role$)
| eval hop=case(userIdentity.arn="$caller_arn$","ORIGIN",true(),"HOP")
| table eventTime sourceIPAddress userIdentity.arn requestParameters.roleArn hop
| sort eventTime`,
      description: 'Maps the complete role assumption chain from origin to final destination. Each row is one hop.',
      fields: ['eventTime', 'sourceIPAddress', 'userIdentity.arn', 'requestParameters.roleArn', 'hop'],
      visualization: 'Directed graph — nodes are IAM roles, edges are AssumeRole events. Color by hop depth.',
    },
    {
      trigger: 'lateral_move fired — what did they do in each account',
      query: `index=aws_cloudtrail
| where userIdentity.arn IN ($caller_arn$, $assumed_role$)
| stats count values(eventName) as actions by awsRegion eventSource
| sort - count`,
      description: 'Shows API call distribution across AWS services and regions for all accounts in the chain.',
      fields: ['awsRegion', 'eventSource', 'count', 'actions'],
      visualization: 'Bubble chart — region/service pairs sized by API call count.',
    },
  ],
  credential_harvest: [
    {
      trigger: 'credential_harvest fired — show all secrets accessed',
      query: `index=aws_cloudtrail eventSource IN ("secretsmanager.amazonaws.com","ssm.amazonaws.com")
userIdentity.arn=$userIdentity.arn$
| stats count by requestParameters.secretId eventName`,
      description: 'Complete list of secrets accessed, with access count per secret.',
      fields: ['requestParameters.secretId', 'eventName', 'count'],
      visualization: 'Table with count bar chart per secret.',
    },
    {
      trigger: 'credential_harvest fired — check if harvested creds were used',
      query: `index=aws_cloudtrail eventName IN ("GetSessionToken","AssumeRole")
userIdentity.arn=$userIdentity.arn$
| stats count by requestParameters.roleArn eventTime
| sort eventTime`,
      description: 'Shows whether harvested credentials were subsequently used to assume roles or get tokens.',
      fields: ['eventTime', 'requestParameters.roleArn', 'count'],
      visualization: 'Timeline — token/role usage over time after credential access.',
    },
  ],
  c2_comms: [
    {
      trigger: 'c2_comms fired — investigate beaconing pattern',
      query: `index=aws_vpcflow srcaddr=$srcaddr$ dstaddr=$dstaddr$
| bin _time span=1m
| stats count by _time dstport
| timechart span=1m count by dstport`,
      description: 'Minute-by-minute connection pattern to the suspicious destination. Check for regular interval beaconing.',
      fields: ['_time', 'dstport', 'count'],
      visualization: 'Timechart with 1-minute granularity. Regular spikes = beaconing.',
    },
    {
      trigger: 'c2_comms fired — check all external destinations from this host',
      query: `index=aws_vpcflow srcaddr=$srcaddr$ action=ACCEPT
| eval dest_internal=if(match(dstaddr,"^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.|^192\\\\.168\\\\."),1,0)
| where dest_internal=0
| stats count sum(bytes) as total_bytes dc(dstport) as ports by dstaddr
| sort - total_bytes`,
      description: 'Complete list of external destinations contacted by this host. Sort by data volume to find exfiltration.',
      fields: ['dstaddr', 'count', 'total_bytes', 'ports'],
      visualization: 'Table sorted by total_bytes descending. Top destinations = potential data exfil.',
    },
  ],
};

export function getHuntQueries(activity: string): HuntQuery[] {
  return HUNT_QUERIES[activity] || [];
}
