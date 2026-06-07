// Regulatory compliance mappings
// GDPR, PCI DSS 4.0, ISO 27001:2022, SOX, HIPAA

export interface RegMapEntry {
  regulation: string;
  article: string;
  requirement: string;
  relevance: string;
  detectionCoverage: string;
}

export interface RegFramework {
  name: string;
  fullName: string;
  applicability: string;
  entries: Record<string, RegMapEntry[]>;
}

export const REGULATORY_FRAMEWORKS: RegFramework[] = [
  {
    name: 'GDPR',
    fullName: 'General Data Protection Regulation (EU)',
    applicability: 'Any organization processing EU personal data',
    entries: {
      delete_data: [
        { regulation: 'GDPR', article: 'Art. 32', requirement: 'Security of processing — implement appropriate technical measures to ensure data security', relevance: 'Mass deletion of personal data is a reportable breach if it affects data subjects\' rights.', detectionCoverage: 'Detecting mass deletion enables 72-hour breach notification compliance.' },
        { regulation: 'GDPR', article: 'Art. 33', requirement: 'Notification of a personal data breach to the supervisory authority within 72 hours', relevance: 'If PII is deleted, notification deadline starts at detection time. Early detection = earlier notification.', detectionCoverage: 'delete_data detection triggers immediate PII exposure assessment.' },
      ],
      s3_exfil: [
        { regulation: 'GDPR', article: 'Art. 32', requirement: 'Security of processing — measures to prevent unauthorized access to personal data', relevance: 'Bulk download of customer PII from S3 is unauthorized processing.', detectionCoverage: 's3_exfil detects bulk unauthorized access to PII-containing storage.' },
        { regulation: 'GDPR', article: 'Art. 33', requirement: 'Data breach notification — 72 hours from discovery', relevance: 'If PII exfiltrated, must notify DPA within 72 hours of detection.', detectionCoverage: 'Volume and sensitivity of exfiltrated data informs notification urgency.' },
        { regulation: 'GDPR', article: 'Art. 34', requirement: 'Communication of breach to data subjects when high risk', relevance: 'If PII exfiltrated poses high risk to rights and freedoms, must notify data subjects directly.', detectionCoverage: 'sensitive_access detection provides data classification needed for Art. 34 assessment.' },
      ] as RegMapEntry[],
      credential_harvest: [
        { regulation: 'GDPR', article: 'Art. 32', requirement: 'Security of processing — authentication and access control measures', relevance: 'Credential harvesting directly undermines access controls protecting personal data.', detectionCoverage: 'credential_harvest detects credential theft before PII is accessed.' },
      ],
    },
  },
  {
    name: 'PCI DSS',
    fullName: 'Payment Card Industry Data Security Standard v4.0',
    applicability: 'Organizations handling cardholder data',
    entries: {
      s3_exfil: [
        { regulation: 'PCI DSS', article: 'Req. 10.2', requirement: 'Audit logging — implement automated audit trails for all access to cardholder data', relevance: 'S3 access logs must capture all GetObject operations on buckets containing PAN data.', detectionCoverage: 's3_exfil monitors all S3 access to buckets potentially containing cardholder data.' },
        { regulation: 'PCI DSS', article: 'Req. 10.6', requirement: 'Review logs — review logs of all system components at least daily', relevance: 'Automated detection replaces manual daily log review with real-time alerting.', detectionCoverage: 'Automated SPL generation enables real-time monitoring of cardholder data access.' },
        { regulation: 'PCI DSS', article: 'Req. 11.4', requirement: 'Intrusion detection/prevention — use automated techniques to detect and alert on suspicious activity', relevance: 'Insider data exfiltration is a form of intrusion requiring detection.', detectionCoverage: 'All CERT/CC insider threat detections satisfy automated suspicious activity monitoring.' },
      ] as RegMapEntry[],
      access_revoke: [
        { regulation: 'PCI DSS', article: 'Req. 7.2', requirement: 'Access control — limit access based on need-to-know', relevance: 'Revoking others\' access to cardholder systems may indicate insider preparing for unauthorized activity.', detectionCoverage: 'access_revoke detection monitors for unauthorized access control changes.' },
      ],
      priv_escalation: [
        { regulation: 'PCI DSS', article: 'Req. 7.1', requirement: 'Limit access to system components and cardholder data to only those individuals whose job requires such access', relevance: 'Privilege escalation bypasses access controls protecting cardholder data.', detectionCoverage: 'priv_escalation detects unauthorized elevation to roles with PAN access.' },
      ],
    },
  },
  {
    name: 'ISO 27001',
    fullName: 'ISO/IEC 27001:2022 — Information Security Management',
    applicability: 'Any organization with ISMS certification',
    entries: {
      delete_data: [
        { regulation: 'ISO 27001', article: 'A.8.13', requirement: 'Information backup — maintain backup copies of information', relevance: 'Mass deletion detection enables rapid backup restoration before data is permanently lost.', detectionCoverage: 'delete_data + backup_destroy detections protect against A.8.13 control failures.' },
      ],
      config_tamper: [
        { regulation: 'ISO 27001', article: 'A.8.9', requirement: 'Configuration management — establish and maintain secure configurations', relevance: 'Tampering with security controls violates configuration management.', detectionCoverage: 'config_tamper detection identifies unauthorized security control modifications.' },
      ],
      log_tamper: [
        { regulation: 'ISO 27001', article: 'A.8.15', requirement: 'Logging — produce, retain, and protect logs', relevance: 'Disabling or deleting logs is a direct violation of logging controls.', detectionCoverage: 'log_tamper detection is a critical compensating control for log integrity.' },
        { regulation: 'ISO 27001', article: 'A.8.16', requirement: 'Monitoring — monitor activities and review logs for anomalies', relevance: 'Automated detection satisfies the monitoring requirement.', detectionCoverage: 'All WaldoHunt detections contribute to A.8.16 monitoring.' },
      ],
      s3_exfil: [
        { regulation: 'ISO 27001', article: 'A.8.12', requirement: 'Data leakage prevention — apply measures to prevent data leakage', relevance: 'Bulk S3 download is a primary data leakage vector.', detectionCoverage: 's3_exfil + data_stage + usb_exfil cover multiple exfiltration channels.' },
      ],
    },
  },
  {
    name: 'HIPAA',
    fullName: 'Health Insurance Portability and Accountability Act',
    applicability: 'Healthcare organizations and business associates handling PHI',
    entries: {
      s3_exfil: [
        { regulation: 'HIPAA', article: '45 CFR §164.308', requirement: 'Administrative safeguards — security management process, risk analysis', relevance: 'PHI exfiltration is a reportable breach under HIPAA Breach Notification Rule.', detectionCoverage: 's3_exfil detects bulk access to S3 buckets containing potential PHI.' },
        { regulation: 'HIPAA', article: '45 CFR §164.312', requirement: 'Technical safeguards — access controls, audit controls, integrity controls', relevance: 'Insider access to PHI must be monitored and controlled.', detectionCoverage: 'sensitive_access detection identifies PHI access patterns.' },
      ],
      sensitive_access: [
        { regulation: 'HIPAA', article: '45 CFR §164.312(b)', requirement: 'Audit controls — implement mechanisms to record and examine activity in information systems containing PHI', relevance: 'Every access to PHI must be logged and reviewed.', detectionCoverage: 'sensitive_access detection provides automated PHI access audit review.' },
      ],
    },
  },
  {
    name: 'SOX',
    fullName: 'Sarbanes-Oxley Act',
    applicability: 'Publicly traded companies',
    entries: {
      financial_manip: [
        { regulation: 'SOX', article: 'Section 302', requirement: 'Corporate responsibility for financial reports — CEO/CFO certify accuracy of financial reports', relevance: 'Financial data manipulation undermines financial reporting integrity.', detectionCoverage: 'financial_manip detection identifies unauthorized billing and cost changes.' },
        { regulation: 'SOX', article: 'Section 404', requirement: 'Management assessment of internal controls over financial reporting', relevance: 'Detection of financial system tampering demonstrates control effectiveness.', detectionCoverage: 'config_tamper + financial_manip detect controls relevant to financial reporting systems.' },
      ],
      log_tamper: [
        { regulation: 'SOX', article: 'Section 404', requirement: 'Internal controls — ensure audit trail integrity for financial systems', relevance: 'Log tampering in financial systems is a material weakness in internal controls.', detectionCoverage: 'log_tamper detection protects financial audit trail integrity.' },
      ],
    },
  },
];

export function getRelevantRegulations(activity: string): RegFramework[] {
  return REGULATORY_FRAMEWORKS.filter(fw => {
    const activityEntries = fw.entries[activity];
    return activityEntries && activityEntries.length > 0;
  });
}

export function getAllRegEntries(activity: string): (RegMapEntry & { framework: string })[] {
  const results: (RegMapEntry & { framework: string })[] = [];
  REGULATORY_FRAMEWORKS.forEach(fw => {
    const entries = fw.entries[activity] || [];
    entries.forEach(e => results.push({ ...e, framework: fw.name }));
  });
  return results;
}
