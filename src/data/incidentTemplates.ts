// Incident ticket templates for ITSM platforms
// ServiceNow, Jira, and Splunk SOAR/TheHive

export interface ServiceNowTemplate {
  shortDescription: string;
  description: string;
  category: string;
  assignmentGroup: string;
  urgency: string;
  impact: string;
  additionalFields: Record<string, string>;
}

export interface JiraTemplate {
  summary: string;
  description: string;
  projectKey: string;
  issueType: string;
  priority: string;
  labels: string[];
  customFields: Record<string, string>;
}

export interface SOARTemplate {
  title: string;
  description: string;
  severity: string;
  tlp: string;
  pap: string;
  tags: string[];
  tasks: string[];
  observables: { dataType: string; data: string; tags: string[] }[];
}

export function generateServiceNow(activity: string, title: string, env: 'aws' | 'onprem', user: string, risk: string): ServiceNowTemplate {
  return {
    shortDescription: `Insider Threat: ${title} — ${user}`,
    description: `WaldoHunt 2.0 Detection Alert\n\nDetection: ${title}\nEnvironment: ${env === 'aws' ? 'AWS Cloud' : 'On-Prem / Hybrid'}\nActivity: ${activity.replace(/_/g, ' ')}\nUser: ${user}\nRisk Level: ${risk}\n\n---\nMITRE ATT&CK TTPs mapped.\n\nImmediate Actions Required:\n1. Verify if activity is authorized (check change management)\n2. Review user's recent activity for additional indicators\n3. Contact user's manager if suspicious\n4. Escalate to SOC Tier 2 if risk = CRITICAL or HIGH\n\nFor full playbook, see: Splunk ES Notable Event drilldown`,
    category: 'Security Incident',
    assignmentGroup: 'Security Operations',
    urgency: risk === 'CRITICAL' ? '1 - Critical' : risk === 'HIGH' ? '2 - High' : '3 - Medium',
    impact: risk === 'CRITICAL' ? '1 - High' : '2 - Medium',
    additionalFields: {
      cmdb_ci: env === 'aws' ? 'AWS Cloud Infrastructure' : 'Corporate IT Infrastructure',
      contact_type: 'Automated Detection',
      assignment_group: 'SOC Tier 2',
      business_service: 'Security Monitoring',
    },
  };
}

export function generateJira(activity: string, title: string, env: 'aws' | 'onprem', user: string, risk: string): JiraTemplate {
  return {
    summary: `[INSIDER] ${title} — ${user} (${risk})`,
    description: `h2. WaldoHunt 2.0 Detection Alert

*Detection:* ${title}
*Environment:* ${env === 'aws' ? 'AWS Cloud' : 'On-Prem / Hybrid'}
*Activity:* ${activity.replace(/_/g, ' ')}
*User:* {{${user}}}
*Risk Level:* ${risk}
*Timestamp:* {{timestamp}}

h2. Immediate Actions
# Verify if activity is authorized (check change management)
# Review user's recent activity for additional indicators
# Contact user's manager if suspicious
# Escalate to SOC Tier 2 if risk = CRITICAL or HIGH

h2. MITRE ATT&CK
See detection brief for full mapping.

h2. Related Detections
Check for correlated alerts: privilege escalation, data staging, lateral movement.`,
    projectKey: 'SEC',
    issueType: 'Incident',
    priority: risk === 'CRITICAL' ? 'Highest' : risk === 'HIGH' ? 'High' : 'Medium',
    labels: ['insider-threat', 'waldohunt', 'automated-detection', activity.replace(/_/g, '-')],
    customFields: {
      customfield_10001: 'SIEM',                     // Detection Source
      customfield_10002: env === 'aws' ? 'Cloud' : 'OnPrem',  // Environment
      customfield_10003: 'SOC Tier 2',              // Assignment Group
    },
  };
}

export function generateSOARCase(activity: string, title: string, env: 'aws' | 'onprem', user: string, risk: string): SOARTemplate {
  const severity = risk === 'CRITICAL' ? '4' : risk === 'HIGH' ? '3' : '2';

  const tasks = [
    `Verify if ${activity.replace(/_/g, ' ')} by ${user} is authorized`,
    `Pull full activity timeline for ${user} over past 72 hours`,
    'Check for correlated alerts (privilege escalation, data staging, lateral movement)',
    'Contact user manager for authorization confirmation',
    risk === 'CRITICAL' ? 'Immediate: revoke active sessions and rotate credentials' : 'Monitor and document',
    'Preserve relevant log evidence to immutable storage',
    'Update incident timeline with findings',
  ];

  const observables = [
    { dataType: 'user-account', data: user, tags: ['source-user', 'insider'] },
    { dataType: 'detection-rule', data: `waldohunt-${env}-${activity}`, tags: ['detection'] },
    { dataType: 'mitre-attack', data: 'T1078', tags: ['ttp'] },
  ];

  return {
    title: `Insider Threat: ${title} — ${user}`,
    description: `WaldoHunt automated detection. Risk: ${risk}. Environment: ${env}. Activity: ${activity}. Full playbook in Splunk ES notable event.`,
    severity,
    tlp: 'AMBER',
    pap: 'RED',
    tags: ['insider-threat', 'waldohunt', 'automated', activity, env],
    tasks,
    observables,
  };
}

export function formatServiceNowJSON(template: ServiceNowTemplate): string {
  return JSON.stringify({
    short_description: template.shortDescription,
    description: template.description,
    category: template.category,
    assignment_group: template.assignmentGroup,
    urgency: template.urgency,
    impact: template.impact,
    ...template.additionalFields,
  }, null, 2);
}

export function formatJiraJSON(template: JiraTemplate): string {
  return JSON.stringify({
    fields: {
      project: { key: template.projectKey },
      summary: template.summary,
      description: template.description,
      issuetype: { name: template.issueType },
      priority: { name: template.priority },
      labels: template.labels,
      ...template.customFields,
    },
  }, null, 2);
}

export function formatSOARJSON(template: SOARTemplate): string {
  return JSON.stringify(template, null, 2);
}
