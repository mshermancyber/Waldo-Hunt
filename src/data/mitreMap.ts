import type { MITREMapType } from '../types';

export const MITRE_MAP: MITREMapType = {
  delete_data: [
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction',                        url: 'https://attack.mitre.org/techniques/T1485/' },
    { tid: 'T1490',   tactic: 'Impact',              technique: 'Inhibit System Recovery',                 url: 'https://attack.mitre.org/techniques/T1490/' },
  ],
  resource_destroy: [
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction',                        url: 'https://attack.mitre.org/techniques/T1485/' },
    { tid: 'T1489',   tactic: 'Impact',              technique: 'Service Stop',                            url: 'https://attack.mitre.org/techniques/T1489/' },
  ],
  config_tamper: [
    { tid: 'T1562.001', tactic: 'Defense Evasion',    technique: 'Disable or Modify Tools',                 url: 'https://attack.mitre.org/techniques/T1562/001/' },
    { tid: 'T1562.002', tactic: 'Defense Evasion',    technique: 'Disable Windows Event Logging',           url: 'https://attack.mitre.org/techniques/T1562/002/' },
  ],
  logic_bomb: [
    { tid: 'T1053.005', tactic: 'Execution / Persistence', technique: 'Scheduled Task/Job',               url: 'https://attack.mitre.org/techniques/T1053/005/' },
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction (deferred)',             url: 'https://attack.mitre.org/techniques/T1485/' },
  ],
  backup_destroy: [
    { tid: 'T1490',   tactic: 'Impact',              technique: 'Inhibit System Recovery',                 url: 'https://attack.mitre.org/techniques/T1490/' },
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction',                        url: 'https://attack.mitre.org/techniques/T1485/' },
  ],
  access_revoke: [
    { tid: 'T1531',   tactic: 'Impact',              technique: 'Account Access Removal',                  url: 'https://attack.mitre.org/techniques/T1531/' },
    { tid: 'T1098',   tactic: 'Persistence',         technique: 'Account Manipulation',                    url: 'https://attack.mitre.org/techniques/T1098/' },
  ],
  s3_exfil: [
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
  ],
  repo_clone: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  secrets_access: [
    { tid: 'T1552.001', tactic: 'Credential Access',  technique: 'Credentials In Files',                   url: 'https://attack.mitre.org/techniques/T1552/001/' },
    { tid: 'T1555',   tactic: 'Credential Access',   technique: 'Credentials from Password Stores',        url: 'https://attack.mitre.org/techniques/T1555/' },
  ],
  data_stage: [
    { tid: 'T1074.002', tactic: 'Collection',         technique: 'Remote Data Staging',                     url: 'https://attack.mitre.org/techniques/T1074/002/' },
    { tid: 'T1020',   tactic: 'Exfiltration',        technique: 'Automated Exfiltration',                  url: 'https://attack.mitre.org/techniques/T1020/' },
  ],
  cross_account: [
    { tid: 'T1078.004', tactic: 'Defense Evasion / Persistence', technique: 'Valid Accounts: Cloud Accounts', url: 'https://attack.mitre.org/techniques/T1078/004/' },
    { tid: 'T1550.001', tactic: 'Lateral Movement',   technique: 'Use Alternate Authentication Material',   url: 'https://attack.mitre.org/techniques/T1550/001/' },
  ],
  usb_exfil: [
    { tid: 'T1052.001', tactic: 'Exfiltration',       technique: 'Exfiltration Over Physical Medium: USB',  url: 'https://attack.mitre.org/techniques/T1052/001/' },
    { tid: 'T1025',   tactic: 'Collection',          technique: 'Data from Removable Media',               url: 'https://attack.mitre.org/techniques/T1025/' },
  ],
  priv_escalation: [
    { tid: 'T1078',   tactic: 'Privilege Escalation', technique: 'Valid Accounts',                        url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1098',   tactic: 'Persistence',         technique: 'Account Manipulation',                    url: 'https://attack.mitre.org/techniques/T1098/' },
  ],
  resource_abuse: [
    { tid: 'T1496',   tactic: 'Impact',              technique: 'Resource Hijacking',                      url: 'https://attack.mitre.org/techniques/T1496/' },
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],
  policy_bypass: [
    { tid: 'T1562',   tactic: 'Defense Evasion',     technique: 'Impair Defenses',                         url: 'https://attack.mitre.org/techniques/T1562/' },
    { tid: 'T1484',   tactic: 'Defense Evasion',     technique: 'Domain or Tenant Policy Modification',    url: 'https://attack.mitre.org/techniques/T1484/' },
  ],
  account_create: [
    { tid: 'T1136.003', tactic: 'Persistence',        technique: 'Create Account: Cloud Account',           url: 'https://attack.mitre.org/techniques/T1136/003/' },
    { tid: 'T1098',   tactic: 'Persistence',         technique: 'Account Manipulation',                    url: 'https://attack.mitre.org/techniques/T1098/' },
  ],
  log_tamper: [
    { tid: 'T1562.002', tactic: 'Defense Evasion',    technique: 'Disable Windows Event Logging',           url: 'https://attack.mitre.org/techniques/T1562/002/' },
    { tid: 'T1070',   tactic: 'Defense Evasion',     technique: 'Indicator Removal',                       url: 'https://attack.mitre.org/techniques/T1070/' },
  ],
  financial_manip: [
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
  ],
  recon: [
    { tid: 'T1580',   tactic: 'Discovery',           technique: 'Cloud Infrastructure Discovery',          url: 'https://attack.mitre.org/techniques/T1580/' },
    { tid: 'T1087',   tactic: 'Discovery',           technique: 'Account Discovery',                       url: 'https://attack.mitre.org/techniques/T1087/' },
    { tid: 'T1526',   tactic: 'Discovery',           technique: 'Cloud Service Discovery',                 url: 'https://attack.mitre.org/techniques/T1526/' },
  ],
  credential_harvest: [
    { tid: 'T1003',   tactic: 'Credential Access',   technique: 'OS Credential Dumping',                   url: 'https://attack.mitre.org/techniques/T1003/' },
    { tid: 'T1528',   tactic: 'Credential Access',   technique: 'Steal Application Access Token',          url: 'https://attack.mitre.org/techniques/T1528/' },
  ],
  sensitive_access: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1039',   tactic: 'Collection',          technique: 'Data from Network Shared Drive',          url: 'https://attack.mitre.org/techniques/T1039/' },
  ],
  lateral_move: [
    { tid: 'T1550.001', tactic: 'Lateral Movement',   technique: 'Use Alternate Authentication Material',   url: 'https://attack.mitre.org/techniques/T1550/001/' },
    { tid: 'T1021',   tactic: 'Lateral Movement',    technique: 'Remote Services',                         url: 'https://attack.mitre.org/techniques/T1021/' },
  ],
  c2_comms: [
    { tid: 'T1071',   tactic: 'Command and Control', technique: 'Application Layer Protocol',              url: 'https://attack.mitre.org/techniques/T1071/' },
    { tid: 'T1048',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Alternative Protocol',  url: 'https://attack.mitre.org/techniques/T1048/' },
  ],
  persistence: [
    { tid: 'T1136',   tactic: 'Persistence',         technique: 'Create Account',                          url: 'https://attack.mitre.org/techniques/T1136/' },
    { tid: 'T1053',   tactic: 'Persistence / Execution', technique: 'Scheduled Task/Job',                url: 'https://attack.mitre.org/techniques/T1053/' },
    { tid: 'T1098',   tactic: 'Persistence',         technique: 'Account Manipulation',                    url: 'https://attack.mitre.org/techniques/T1098/' },
  ],

  // === DATA MANIPULATION ===
  report_falsify: [
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],
  model_poison: [
    { tid: 'T1565.003', tactic: 'Impact',            technique: 'Data Manipulation: Runtime Data',         url: 'https://attack.mitre.org/techniques/T1565/003/' },
    { tid: 'T1496',   tactic: 'Impact',              technique: 'Resource Hijacking',                      url: 'https://attack.mitre.org/techniques/T1496/' },
  ],
  txn_manip: [
    { tid: 'T1565.001', tactic: 'Impact',            technique: 'Data Manipulation: Stored Data',         url: 'https://attack.mitre.org/techniques/T1565/001/' },
    { tid: 'T1565.002', tactic: 'Impact',            technique: 'Data Manipulation: Transmitted Data',    url: 'https://attack.mitre.org/techniques/T1565/002/' },
  ],
  record_alter: [
    { tid: 'T1565.001', tactic: 'Impact',            technique: 'Data Manipulation: Stored Data',         url: 'https://attack.mitre.org/techniques/T1565/001/' },
    { tid: 'T1070',   tactic: 'Defense Evasion',     technique: 'Indicator Removal',                       url: 'https://attack.mitre.org/techniques/T1070/' },
  ],
  data_poison: [
    { tid: 'T1565.001', tactic: 'Impact',            technique: 'Data Manipulation: Stored Data',         url: 'https://attack.mitre.org/techniques/T1565/001/' },
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction',                        url: 'https://attack.mitre.org/techniques/T1485/' },
  ],
  metric_manip: [
    { tid: 'T1562',   tactic: 'Defense Evasion',     technique: 'Impair Defenses',                         url: 'https://attack.mitre.org/techniques/T1562/' },
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
  ],

  // === EXTENDED IT SABOTAGE ===
  ransomware_deploy: [
    { tid: 'T1486',   tactic: 'Impact',              technique: 'Data Encrypted for Impact',               url: 'https://attack.mitre.org/techniques/T1486/' },
    { tid: 'T1490',   tactic: 'Impact',              technique: 'Inhibit System Recovery',                 url: 'https://attack.mitre.org/techniques/T1490/' },
  ],
  system_overload: [
    { tid: 'T1498',   tactic: 'Impact',              technique: 'Network Denial of Service',               url: 'https://attack.mitre.org/techniques/T1498/' },
    { tid: 'T1499',   tactic: 'Impact',              technique: 'Endpoint Denial of Service',              url: 'https://attack.mitre.org/techniques/T1499/' },
  ],

  // === EXTENDED IP THEFT ===
  email_exfil: [
    { tid: 'T1048.002', tactic: 'Exfiltration',     technique: 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol', url: 'https://attack.mitre.org/techniques/T1048/002/' },
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
  ],
  print_exfil: [
    { tid: 'T1052',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Physical Medium',       url: 'https://attack.mitre.org/techniques/T1052/' },
    { tid: 'T1025',   tactic: 'Collection',          technique: 'Data from Removable Media',               url: 'https://attack.mitre.org/techniques/T1025/' },
  ],
  cloud_sync: [
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  screen_capture: [
    { tid: 'T1113',   tactic: 'Collection',          technique: 'Screen Capture',                          url: 'https://attack.mitre.org/techniques/T1113/' },
    { tid: 'T1125',   tactic: 'Collection',          technique: 'Video Capture',                           url: 'https://attack.mitre.org/techniques/T1125/' },
  ],

  // === EXTENDED FRAUD ===
  payroll_manip: [
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],
  vendor_collusion: [
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
    { tid: 'T1078',   tactic: 'Privilege Escalation',technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],
  expense_fraud: [
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],

  // === EXTENDED ESPIONAGE ===
  document_hoarding: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1039',   tactic: 'Collection',          technique: 'Data from Network Shared Drive',          url: 'https://attack.mitre.org/techniques/T1039/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  meeting_infil: [
    { tid: 'T1598',   tactic: 'Reconnaissance',      technique: 'Phishing for Information',                url: 'https://attack.mitre.org/techniques/T1598/' },
    { tid: 'T1199',   tactic: 'Persistence',         technique: 'Trusted Relationship',                    url: 'https://attack.mitre.org/techniques/T1199/' },
  ],

  // === THIRD PARTY ===
  vendor_abuse: [
    { tid: 'T1078',   tactic: 'Initial Access',      technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1199',   tactic: 'Initial Access',      technique: 'Trusted Relationship',                    url: 'https://attack.mitre.org/techniques/T1199/' },
  ],
  msp_pivot: [
    { tid: 'T1078',   tactic: 'Lateral Movement',    technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1021',   tactic: 'Lateral Movement',    technique: 'Remote Services',                         url: 'https://attack.mitre.org/techniques/T1021/' },
  ],
  credential_share: [
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1550.001', tactic: 'Defense Evasion',   technique: 'Use Alternate Authentication Material',   url: 'https://attack.mitre.org/techniques/T1550/001/' },
  ],
  partner_scrape: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  supply_chain_insert: [
    { tid: 'T1195.001', tactic: 'Initial Access',    technique: 'Supply Chain Compromise: Software Dependencies', url: 'https://attack.mitre.org/techniques/T1195/001/' },
    { tid: 'T1199',   tactic: 'Initial Access',      technique: 'Trusted Relationship',                    url: 'https://attack.mitre.org/techniques/T1199/' },
  ],
  off_hours_contractor: [
    { tid: 'T1078',   tactic: 'Initial Access',      technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
    { tid: 'T1199',   tactic: 'Defense Evasion',     technique: 'Trusted Relationship',                    url: 'https://attack.mitre.org/techniques/T1199/' },
  ],

  // === UNAUTHORIZED DISCLOSURE ===
  media_leak: [
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
    { tid: 'T1048',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Alternative Protocol',  url: 'https://attack.mitre.org/techniques/T1048/' },
  ],
  whistleblower_collect: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  social_media_post: [
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
    { tid: 'T1071',   tactic: 'Command and Control', technique: 'Application Layer Protocol',              url: 'https://attack.mitre.org/techniques/T1071/' },
  ],
  competitor_transfer: [
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
    { tid: 'T1567',   tactic: 'Exfiltration',        technique: 'Exfiltration Over Web Service',           url: 'https://attack.mitre.org/techniques/T1567/' },
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
  ],

  cert_manipulation: [
    { tid: 'T1553',   tactic: 'Defense Evasion',     technique: 'Subvert Trust Controls',                  url: 'https://attack.mitre.org/techniques/T1553/' },
    { tid: 'T1587.003',tactic:'Resource Development',technique: 'Code Signing Certificates',              url: 'https://attack.mitre.org/techniques/T1587/003/' },
  ],
  network_reconfig: [
    { tid: 'T1562.004',tactic:'Defense Evasion',     technique: 'Disable or Modify System Firewall',        url: 'https://attack.mitre.org/techniques/T1562/004/' },
    { tid: 'T1498',   tactic: 'Impact',              technique: 'Network Denial of Service',               url: 'https://attack.mitre.org/techniques/T1498/' },
  ],
  database_dump: [
    { tid: 'T1213',   tactic: 'Collection',          technique: 'Data from Information Repositories',      url: 'https://attack.mitre.org/techniques/T1213/' },
    { tid: 'T1530',   tactic: 'Collection',          technique: 'Data from Cloud Storage',                 url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  backdoor_maintenance: [
    { tid: 'T1136',   tactic: 'Persistence',         technique: 'Create Account',                          url: 'https://attack.mitre.org/techniques/T1136/' },
    { tid: 'T1098',   tactic: 'Persistence',         technique: 'Account Manipulation',                    url: 'https://attack.mitre.org/techniques/T1098/' },
  ],
  evidence_destruction: [
    { tid: 'T1070',   tactic: 'Defense Evasion',     technique: 'Indicator Removal',                       url: 'https://attack.mitre.org/techniques/T1070/' },
    { tid: 'T1485',   tactic: 'Impact',              technique: 'Data Destruction',                        url: 'https://attack.mitre.org/techniques/T1485/' },
    { tid: 'T1562',   tactic: 'Defense Evasion',     technique: 'Impair Defenses',                         url: 'https://attack.mitre.org/techniques/T1562/' },
  ],
  regulatory_filing_manip: [
    { tid: 'T1565',   tactic: 'Impact',              technique: 'Data Manipulation',                       url: 'https://attack.mitre.org/techniques/T1565/' },
    { tid: 'T1078',   tactic: 'Defense Evasion',     technique: 'Valid Accounts',                          url: 'https://attack.mitre.org/techniques/T1078/' },
  ],
  digital_stalking: [
    { tid: 'T1598',   tactic: 'Reconnaissance',      technique: 'Phishing for Information',                url: 'https://attack.mitre.org/techniques/T1598/' },
    { tid: 'T1580',   tactic: 'Discovery',           technique: 'Cloud Infrastructure Discovery',          url: 'https://attack.mitre.org/techniques/T1580/' },
  ],
  threat_comms: [
    { tid: 'T1598',   tactic: 'Reconnaissance',      technique: 'Phishing for Information',                url: 'https://attack.mitre.org/techniques/T1598/' },
    { tid: 'T1204',   tactic: 'Execution',           technique: 'User Execution',                          url: 'https://attack.mitre.org/techniques/T1204/' },
  ],
  unauthorized_surveillance: [
    { tid: 'T1113',   tactic: 'Collection',          technique: 'Screen Capture',                          url: 'https://attack.mitre.org/techniques/T1113/' },
    { tid: 'T1125',   tactic: 'Collection',          technique: 'Video Capture',                           url: 'https://attack.mitre.org/techniques/T1125/' },
  ],
};
