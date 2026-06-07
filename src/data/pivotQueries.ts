// Investigation timeline configuration per detection
// Fields for Splunk timeline visualization and risk score aggregation

export interface InvestigationTimeline {
  xField: string;
  yFields: string[];
  splitBy: string;
  drilldownSearch: string;
  annotations: { label: string; search: string }[];
}

export const INVESTIGATION_TIMELINES: Record<string, InvestigationTimeline> = {
  delete_data: {
    xField: '_time',
    yFields: ['delete_count'],
    splitBy: 'bucketName',
    drilldownSearch: `index=aws_cloudtrail sourcetype=aws:cloudtrail userIdentity.arn="$userIdentity.arn$" eventName IN ("DeleteObject","DeleteObjects","DeleteBucket")`,
    annotations: [
      { label: 'First deletion observed', search: '| head 1 | eval annotation="Start of deletion activity"' },
      { label: 'Peak deletion rate', search: '| stats max(delete_count) as peak by _time | sort - peak | head 1' },
    ],
  },
  s3_exfil: {
    xField: '_time',
    yFields: ['download_count', 'total_gb'],
    splitBy: 'bucket',
    drilldownSearch: `index=aws_s3_accesslogs sourcetype=aws:s3:accesslogs requester="$requester$" operation="REST.GET.OBJECT"`,
    annotations: [
      { label: 'Exfiltration begins', search: '| streamstats sum(total_bytes) as cumulative_bytes | where cumulative_bytes > 104857600 | head 1' },
      { label: '1 GB threshold crossed', search: '| streamstats sum(total_bytes) as cumulative_bytes | where cumulative_bytes > 1073741824 | head 1' },
    ],
  },
  priv_escalation: {
    xField: 'eventTime',
    yFields: ['count'],
    splitBy: 'eventName',
    drilldownSearch: `index=aws_cloudtrail sourcetype=aws:cloudtrail userIdentity.arn="$userIdentity.arn$" eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","CreateAccessKey","AddUserToGroup")`,
    annotations: [
      { label: 'First escalation action', search: '| head 1' },
      { label: 'Admin policy attached', search: '| search eventName="AttachUserPolicy" requestParameters.policyArn="*AdministratorAccess*" | head 1' },
    ],
  },
  lateral_move: {
    xField: 'eventTime',
    yFields: ['roles_assumed', 'cross_account_count'],
    splitBy: 'targetAccount',
    drilldownSearch: `index=aws_cloudtrail sourcetype=aws:cloudtrail eventName="AssumeRole" userIdentity.arn="$caller_arn$" OR requestParameters.roleArn="$assumed_role$"`,
    annotations: [
      { label: 'First cross-account AssumeRole', search: '| where target_account!=aws_account_id | head 1' },
      { label: 'Production account reached', search: '| search requestParameters.roleArn="*:role/ProductionAdmin" | head 1' },
    ],
  },
  credential_harvest: {
    xField: 'eventTime',
    yFields: ['access_count'],
    splitBy: 'secretId',
    drilldownSearch: `index=aws_cloudtrail sourcetype=aws:cloudtrail userIdentity.arn="$userIdentity.arn$" eventSource IN ("secretsmanager.amazonaws.com","ssm.amazonaws.com")`,
    annotations: [
      { label: 'First secret accessed', search: '| head 1' },
      { label: 'Session token obtained', search: '| search eventName="GetSessionToken" | head 1' },
    ],
  },
};

// Risk score aggregation — compound user risk
export interface AggregatedRisk {
  user: string;
  detections: { activity: string; riskScore: number; severity: string }[];
  totalScore: number;
  maxSeverity: string;
  escalationRecommended: boolean;
}

export function aggregateRisk(
  user: string,
  triggeredDetections: { activity: string; riskScore: number; severity: string }[]
): AggregatedRisk {
  const totalScore = triggeredDetections.reduce((sum, d) => sum + d.riskScore, 0);
  const severities = triggeredDetections.map(d => d.severity);
  const maxSeverity = severities.includes('critical') ? 'critical'
    : severities.includes('high') ? 'high'
    : severities.includes('medium') ? 'medium' : 'low';

  return {
    user,
    detections: triggeredDetections,
    totalScore,
    maxSeverity,
    escalationRecommended: totalScore >= 150 || maxSeverity === 'critical',
  };
}

export function generateAggregationSPL(triggeredDetections: string[]): string {
  const detectionSearches = triggeredDetections.map((act, i) =>
    `| append [ | inputlookup risk_scores_${act} | eval detection="${act.replace(/_/g, ' ')}" ]`
  ).join('\n');

  return `| tstats sum(risk_score) as compound_score
    dc(detection) as detection_count
    values(detection) as detections
    values(severity) as severities
    from datamodel=Risk.All_Risk
    where risk_object_type="user" AND (${triggeredDetections.map(d => `detection="${d}"`).join(' OR ')})
  by risk_object
| eval max_severity=case(
    like(severities,"%critical%"),"CRITICAL",
    like(severities,"%high%"),"HIGH",
    like(severities,"%medium%"),"MEDIUM",
    true(),"LOW")
| eval escalate=if(compound_score >= 150 OR max_severity="CRITICAL","YES","NO")
| where compound_score >= 50
| sort - compound_score
| table risk_object compound_score detection_count detections max_severity escalate`;
}
