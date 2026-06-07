// Risk-Based Alerting (RBA) configuration per detection
// Splunk ES risk framework — risk scores, object types, decay functions

export interface RBAConfig {
  riskObject: string;
  riskObjectField: string;
  riskScore: number;
  riskScoreClamp: { min: number; max: number };
  decayFunction: string;
  decayWindow: string;
  urgency: string;
  priority: string;
  alertAction: string;
}

export function generateRBAConfig(activity: string): RBAConfig {
  const defaults: Record<string, Partial<RBAConfig>> = {
    priv_escalation: {
      riskScore: 90, riskObject: 'user', riskObjectField: 'userIdentity.arn',
      urgency: 'critical', priority: 'P1', alertAction: 'notable,email,soar',
      decayWindow: '30d',
    },
    credential_harvest: {
      riskScore: 85, riskObject: 'user', riskObjectField: 'userIdentity.arn',
      urgency: 'critical', priority: 'P1', alertAction: 'notable,email',
      decayWindow: '30d',
    },
    log_tamper: {
      riskScore: 95, riskObject: 'user', riskObjectField: 'userIdentity.arn',
      urgency: 'critical', priority: 'P1', alertAction: 'notable,email,soar',
      decayWindow: '90d',
    },
    delete_data: {
      riskScore: 75, riskObject: 'user', riskObjectField: 'userIdentity.arn',
      urgency: 'high', priority: 'P2', alertAction: 'notable,soar',
      decayWindow: '14d',
    },
    resource_destroy: {
      riskScore: 70, riskObject: 'user', riskObjectField: 'userIdentity.arn',
      urgency: 'high', priority: 'P2', alertAction: 'notable',
      decayWindow: '14d',
    },
    s3_exfil: {
      riskScore: 65, riskObject: 'user', riskObjectField: 'requester',
      urgency: 'medium', priority: 'P3', alertAction: 'notable',
      decayWindow: '7d',
    },
    lateral_move: {
      riskScore: 75, riskObject: 'user', riskObjectField: 'caller_arn',
      urgency: 'high', priority: 'P2', alertAction: 'notable,soar',
      decayWindow: '14d',
    },
    c2_comms: { riskScore: 80, riskObject: 'system', riskObjectField: 'srcaddr', urgency: 'high', priority: 'P2', alertAction: 'notable,soar', decayWindow: '14d' },
    persistence: { riskScore: 70, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable', decayWindow: '30d' },
    usb_exfil: { riskScore: 75, riskObject: 'user', riskObjectField: 'SubjectUserName', urgency: 'high', priority: 'P2', alertAction: 'notable', decayWindow: '14d' },
    data_stage: { riskScore: 60, riskObject: 'user', riskObjectField: 'user_name', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    recon: { riskScore: 40, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'low', priority: 'P4', alertAction: 'risk_only', decayWindow: '3d' },
    repo_clone: { riskScore: 55, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    config_tamper: { riskScore: 80, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable,email', decayWindow: '14d' },
    cross_account: { riskScore: 65, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    backup_destroy: { riskScore: 80, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable,email', decayWindow: '30d' },
    access_revoke: { riskScore: 75, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable', decayWindow: '14d' },
    secrets_access: { riskScore: 65, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    sensitive_access: { riskScore: 60, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    resource_abuse: { riskScore: 50, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'low', priority: 'P4', alertAction: 'risk_only', decayWindow: '7d' },
    policy_bypass: { riskScore: 70, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable', decayWindow: '14d' },
    account_create: { riskScore: 55, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'medium', priority: 'P3', alertAction: 'notable', decayWindow: '7d' },
    financial_manip: { riskScore: 70, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'high', priority: 'P2', alertAction: 'notable,email', decayWindow: '14d' },
    logic_bomb: { riskScore: 85, riskObject: 'user', riskObjectField: 'userIdentity.arn', urgency: 'critical', priority: 'P1', alertAction: 'notable,email,soar', decayWindow: '90d' },
  };

  const config = defaults[activity] || {
    riskScore: 50, riskObject: 'user', riskObjectField: 'user',
    urgency: 'medium', priority: 'P3', alertAction: 'notable',
    decayWindow: '14d',
  };

  return {
    riskObject: config.riskObject || 'user',
    riskObjectField: config.riskObjectField || 'user',
    riskScore: config.riskScore || 50,
    riskScoreClamp: { min: 0, max: 100 },
    decayFunction: 'exponential',
    decayWindow: config.decayWindow || '14d',
    urgency: config.urgency || 'medium',
    priority: config.priority || 'P3',
    alertAction: config.alertAction || 'notable',
  };
}

export function generateRBAStanza(activity: string, spl: string): string {
  const config = generateRBAConfig(activity);
  return `# Risk-Based Alerting configuration for: ${activity}
# Paste this into your Splunk ES correlation search configuration

[risk_correlation]
risk_object = ${config.riskObject}
risk_object_field = ${config.riskObjectField}
risk_score = ${config.riskScore}

[risk_scoring]
decay_function = ${config.decayFunction}
decay_window = ${config.decayWindow}
score_clamp_min = ${config.riskScoreClamp.min}
score_clamp_max = ${config.riskScoreClamp.max}

[alert]
urgency = ${config.urgency}
priority = ${config.priority}
alert_action = ${config.alertAction}

# Correlation search SPL:
# ${spl.split('\n')[0]}
`;
}
