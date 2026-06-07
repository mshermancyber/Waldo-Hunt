// NIST 800-53 Rev 5 + CIS Controls v8 mappings for insider threat detections

export interface ControlMapping {
  nist80053: { id: string; title: string; family: string }[];
  cis8: { id: string; title: string; ig: string }[];
}

export const COMPLIANCE_MAP: Record<string, ControlMapping> = {
  delete_data: {
    nist80053: [
      { id: 'CP-6', title: 'Alternate Storage Site', family: 'Contingency Planning' },
      { id: 'CP-9', title: 'System Backup', family: 'Contingency Planning' },
      { id: 'SI-7', title: 'Software, Firmware, and Information Integrity', family: 'System and Information Integrity' },
      { id: 'AU-12', title: 'Audit Record Generation', family: 'Audit and Accountability' },
    ],
    cis8: [
      { id: '11.1', title: 'Establish and Maintain a Data Recovery Process', ig: 'IG2' },
      { id: '8.2', title: 'Collect Audit Logs', ig: 'IG1' },
      { id: '8.5', title: 'Collect Detailed Audit Logs', ig: 'IG2' },
    ],
  },
  resource_destroy: {
    nist80053: [
      { id: 'CP-2', title: 'Contingency Plan', family: 'Contingency Planning' },
      { id: 'CP-10', title: 'System Recovery and Reconstitution', family: 'Contingency Planning' },
      { id: 'AC-6', title: 'Least Privilege', family: 'Access Control' },
    ],
    cis8: [
      { id: '5.4', title: 'Restrict Administrator Privileges to Dedicated Administrator Accounts', ig: 'IG1' },
      { id: '11.1', title: 'Establish and Maintain a Data Recovery Process', ig: 'IG2' },
    ],
  },
  config_tamper: {
    nist80053: [
      { id: 'AU-6', title: 'Audit Record Review, Analysis, and Reporting', family: 'Audit and Accountability' },
      { id: 'AU-9', title: 'Protection of Audit Information', family: 'Audit and Accountability' },
      { id: 'CM-3', title: 'Configuration Change Control', family: 'Configuration Management' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '4.1', title: 'Establish and Maintain a Secure Configuration Process', ig: 'IG1' },
      { id: '8.2', title: 'Collect Audit Logs', ig: 'IG1' },
      { id: '8.11', title: 'Establish and Maintain Detailed Audit Log Management', ig: 'IG3' },
    ],
  },
  logic_bomb: {
    nist80053: [
      { id: 'SI-3', title: 'Malicious Code Protection', family: 'System and Information Integrity' },
      { id: 'CM-11', title: 'User-Installed Software', family: 'Configuration Management' },
      { id: 'AU-6', title: 'Audit Record Review', family: 'Audit and Accountability' },
    ],
    cis8: [
      { id: '10.1', title: 'Deploy and Maintain Anti-Malware Software', ig: 'IG1' },
      { id: '10.7', title: 'Use Behavior-Based Anti-Malware Software', ig: 'IG3' },
    ],
  },
  backup_destroy: {
    nist80053: [
      { id: 'CP-9', title: 'System Backup', family: 'Contingency Planning' },
      { id: 'CP-6', title: 'Alternate Storage Site', family: 'Contingency Planning' },
      { id: 'IR-4', title: 'Incident Handling', family: 'Incident Response' },
    ],
    cis8: [
      { id: '11.1', title: 'Establish and Maintain a Data Recovery Process', ig: 'IG2' },
      { id: '11.2', title: 'Establish and Maintain an Isolated Recovery Environment', ig: 'IG3' },
    ],
  },
  access_revoke: {
    nist80053: [
      { id: 'AC-2', title: 'Account Management', family: 'Access Control' },
      { id: 'AC-3', title: 'Access Enforcement', family: 'Access Control' },
      { id: 'IR-4', title: 'Incident Handling', family: 'Incident Response' },
    ],
    cis8: [
      { id: '5.3', title: 'Disable Dormant Accounts', ig: 'IG1' },
      { id: '6.8', title: 'Define and Maintain Role-Based Access Control', ig: 'IG2' },
    ],
  },
  s3_exfil: {
    nist80053: [
      { id: 'AC-4', title: 'Information Flow Enforcement', family: 'Access Control' },
      { id: 'AU-12', title: 'Audit Record Generation', family: 'Audit and Accountability' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
      { id: 'SC-7', title: 'Boundary Protection', family: 'System and Communications Protection' },
    ],
    cis8: [
      { id: '3.12', title: 'Segment Data Processing and Storage Based on Sensitivity', ig: 'IG3' },
      { id: '8.5', title: 'Collect Detailed Audit Logs', ig: 'IG2' },
      { id: '13.1', title: 'Centralize Security Event Alerting', ig: 'IG2' },
    ],
  },
  repo_clone: {
    nist80053: [
      { id: 'AC-4', title: 'Information Flow Enforcement', family: 'Access Control' },
      { id: 'CM-8', title: 'System Component Inventory', family: 'Configuration Management' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '3.3', title: 'Document Data Flows', ig: 'IG2' },
      { id: '13.6', title: 'Collect Network Traffic Flow Logs', ig: 'IG2' },
    ],
  },
  priv_escalation: {
    nist80053: [
      { id: 'AC-2', title: 'Account Management', family: 'Access Control' },
      { id: 'AC-5', title: 'Separation of Duties', family: 'Access Control' },
      { id: 'AC-6', title: 'Least Privilege', family: 'Access Control' },
      { id: 'IA-2', title: 'Identification and Authentication', family: 'Identification and Authentication' },
    ],
    cis8: [
      { id: '5.4', title: 'Restrict Administrator Privileges to Dedicated Administrator Accounts', ig: 'IG1' },
      { id: '5.5', title: 'Establish and Maintain an Inventory of Administrative Accounts', ig: 'IG2' },
      { id: '6.8', title: 'Define and Maintain Role-Based Access Control', ig: 'IG2' },
    ],
  },
  resource_abuse: {
    nist80053: [
      { id: 'AC-6', title: 'Least Privilege', family: 'Access Control' },
      { id: 'CM-11', title: 'User-Installed Software', family: 'Configuration Management' },
      { id: 'SC-4', title: 'Information in Shared Resources', family: 'System and Communications Protection' },
    ],
    cis8: [
      { id: '5.4', title: 'Restrict Administrator Privileges', ig: 'IG1' },
      { id: '2.3', title: 'Address Unauthorized Assets', ig: 'IG1' },
    ],
  },
  policy_bypass: {
    nist80053: [
      { id: 'AC-3', title: 'Access Enforcement', family: 'Access Control' },
      { id: 'CM-3', title: 'Configuration Change Control', family: 'Configuration Management' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '4.1', title: 'Establish and Maintain a Secure Configuration Process', ig: 'IG1' },
      { id: '4.4', title: 'Implement and Manage a Firewall on Servers', ig: 'IG2' },
    ],
  },
  log_tamper: {
    nist80053: [
      { id: 'AU-9', title: 'Protection of Audit Information', family: 'Audit and Accountability' },
      { id: 'AU-10', title: 'Non-repudiation', family: 'Audit and Accountability' },
      { id: 'AU-11', title: 'Audit Record Retention', family: 'Audit and Accountability' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '8.2', title: 'Collect Audit Logs', ig: 'IG1' },
      { id: '8.3', title: 'Ensure Adequate Audit Log Storage', ig: 'IG1' },
      { id: '8.9', title: 'Centralize Audit Logs', ig: 'IG2' },
    ],
  },
  recon: {
    nist80053: [
      { id: 'RA-5', title: 'Vulnerability Monitoring and Scanning', family: 'Risk Assessment' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
      { id: 'AC-6', title: 'Least Privilege', family: 'Access Control' },
    ],
    cis8: [
      { id: '8.5', title: 'Collect Detailed Audit Logs', ig: 'IG2' },
      { id: '13.1', title: 'Centralize Security Event Alerting', ig: 'IG2' },
      { id: '16.13', title: 'Conduct Penetration Tests', ig: 'IG3' },
    ],
  },
  credential_harvest: {
    nist80053: [
      { id: 'IA-5', title: 'Authenticator Management', family: 'Identification and Authentication' },
      { id: 'IA-6', title: 'Authenticator Feedback', family: 'Identification and Authentication' },
      { id: 'AC-6', title: 'Least Privilege', family: 'Access Control' },
    ],
    cis8: [
      { id: '5.5', title: 'Establish and Maintain an Inventory of Administrative Accounts', ig: 'IG2' },
      { id: '6.2', title: 'Establish and Maintain an Inventory of Accounts', ig: 'IG1' },
      { id: '16.2', title: 'Establish and Maintain a Penetration Testing Program', ig: 'IG3' },
    ],
  },
  lateral_move: {
    nist80053: [
      { id: 'AC-4', title: 'Information Flow Enforcement', family: 'Access Control' },
      { id: 'AC-17', title: 'Remote Access', family: 'Access Control' },
      { id: 'SC-7', title: 'Boundary Protection', family: 'System and Communications Protection' },
    ],
    cis8: [
      { id: '4.4', title: 'Implement and Manage a Firewall on Servers', ig: 'IG2' },
      { id: '12.2', title: 'Establish and Maintain a Secure Network Architecture', ig: 'IG2' },
      { id: '12.4', title: 'Deny Communication Over Unauthorized Ports', ig: 'IG2' },
    ],
  },
  c2_comms: {
    nist80053: [
      { id: 'SC-7', title: 'Boundary Protection', family: 'System and Communications Protection' },
      { id: 'SC-8', title: 'Transmission Confidentiality and Integrity', family: 'System and Communications Protection' },
      { id: 'SI-4', title: 'System Monitoring', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '9.2', title: 'Ensure Only Approved Ports, Protocols, and Services Are Listening', ig: 'IG1' },
      { id: '12.6', title: 'Use of Encrypted Network Protocols', ig: 'IG2' },
      { id: '13.7', title: 'Deploy a Host-Based Intrusion Detection Solution', ig: 'IG2' },
    ],
  },
  persistence: {
    nist80053: [
      { id: 'AC-2', title: 'Account Management', family: 'Access Control' },
      { id: 'CM-11', title: 'User-Installed Software', family: 'Configuration Management' },
      { id: 'SI-3', title: 'Malicious Code Protection', family: 'System and Information Integrity' },
    ],
    cis8: [
      { id: '5.1', title: 'Establish and Maintain an Inventory of Accounts', ig: 'IG1' },
      { id: '5.5', title: 'Establish and Maintain an Inventory of Administrative Accounts', ig: 'IG2' },
      { id: '10.7', title: 'Use Behavior-Based Anti-Malware Software', ig: 'IG3' },
    ],
  },
};

// Full traceability: CERT Pattern → Activity → MITRE → NIST → CIS
export interface TraceabilityRow {
  certPattern: string;
  activity: string;
  mitreTtp: string;
  mitreTactic: string;
  nistControl: string;
  cisControl: string;
}

export function buildTraceability(
  pattern: string,
  activities: string[],
  mitreTtps: { tid: string; tactic: string }[]
): TraceabilityRow[] {
  const patternName: Record<string, string> = {
    sabotage: 'IT Sabotage',
    ip_theft: 'IP Theft',
    fraud: 'Fraud',
    espionage: 'Espionage',
  };
  return mitreTtps.map((t) => {
    const compMap = COMPLIANCE_MAP[activities[0]] || COMPLIANCE_MAP.delete_data;
    return {
      certPattern: patternName[pattern] || pattern,
      activity: activities[0] || '',
      mitreTtp: t.tid,
      mitreTactic: t.tactic,
      nistControl: compMap.nist80053.map((n) => n.id).join(', '),
      cisControl: compMap.cis8.map((c) => c.id).join(', '),
    };
  });
}
