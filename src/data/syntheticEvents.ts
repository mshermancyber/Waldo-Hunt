// Synthetic event generator — produces realistic log events to test SPL detections
// CloudTrail JSON, Windows Event XML, and EDR event formats

export interface SyntheticEvent {
  format: 'cloudtrail' | 'winevent' | 'edr' | 'proxy' | 'dlp';
  raw: string;
  description: string;
  shouldTrigger: boolean;
}

interface EventTemplate {
  cloudtrail: (userArn: string, sourceIp: string, region: string) => string;
  winevent: (user: string, domain: string, computer: string, ip: string) => string;
  edr: (user: string, computer: string) => string;
  proxy: (user: string, ip: string) => string;
  dlp: (user: string, endpoint: string) => string;
}

function cloudtrailEvent(eventName: string, overrides: Record<string, string> = {}): string {
  const base = {
    eventVersion: '1.08',
    userIdentity: { type: 'IAMUser', arn: overrides.userArn || 'arn:aws:iam::123456789012:user/jdoe', accountId: '123456789012' },
    eventTime: overrides.eventTime || new Date().toISOString(),
    eventSource: overrides.eventSource || 'ec2.amazonaws.com',
    eventName,
    awsRegion: overrides.awsRegion || 'us-east-1',
    sourceIPAddress: overrides.sourceIPAddress || '203.0.113.42',
    userAgent: overrides.userAgent || 'console.amazonaws.com',
    requestParameters: overrides.requestParameters ? JSON.parse(overrides.requestParameters) : {},
    responseElements: {},
  };
  return JSON.stringify(base);
}

export function generateSyntheticEvents(activity: string, env: 'aws' | 'onprem', count: number = 10): SyntheticEvent[] {
  const events: SyntheticEvent[] = [];
  const maliciousUser = env === 'aws' ? 'arn:aws:iam::123456789012:user/insider_threat' : 'INSIDER\\jsmith';
  const normalUser = env === 'aws' ? 'arn:aws:iam::123456789012:user/normal_user' : 'CORP\\jdoe';
  const suspiciousIp = '198.51.100.77';
  const normalIp = '10.0.1.50';

  if (env === 'aws') {
    switch (activity) {
      case 'delete_data':
        // Malicious: mass delete
        for (let i = 0; i < Math.floor(count * 0.7); i++) {
          events.push({
            format: 'cloudtrail',
            shouldTrigger: true,
            description: `Malicious bulk delete of S3 object #${i + 1}`,
            raw: cloudtrailEvent('DeleteObject', {
              userArn: maliciousUser,
              sourceIPAddress: suspiciousIp,
              eventSource: 's3.amazonaws.com',
              requestParameters: JSON.stringify({ bucketName: 'production-data', key: `sensitive/project_alpha/file_${i}.dat` }),
            }),
          });
        }
        // Benign: single delete by normal user
        for (let i = 0; i < Math.floor(count * 0.3); i++) {
          events.push({
            format: 'cloudtrail',
            shouldTrigger: false,
            description: 'Benign single object cleanup by normal user',
            raw: cloudtrailEvent('DeleteObject', {
              userArn: normalUser,
              sourceIPAddress: normalIp,
              eventSource: 's3.amazonaws.com',
              requestParameters: JSON.stringify({ bucketName: 'temp-logs', key: `test/cleanup_${i}.tmp` }),
            }),
          });
        }
        break;

      case 'priv_escalation':
        events.push({
          format: 'cloudtrail', shouldTrigger: true,
          description: 'CRITICAL: AttachAdministratorAccess policy to user',
          raw: cloudtrailEvent('AttachUserPolicy', {
            userArn: maliciousUser,
            sourceIPAddress: suspiciousIp,
            eventSource: 'iam.amazonaws.com',
            requestParameters: JSON.stringify({ userName: 'insider_threat', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }),
          }),
        });
        events.push({
          format: 'cloudtrail', shouldTrigger: true,
          description: 'CreateAccessKey for persistence',
          raw: cloudtrailEvent('CreateAccessKey', {
            userArn: maliciousUser,
            sourceIPAddress: suspiciousIp,
            eventSource: 'iam.amazonaws.com',
            requestParameters: JSON.stringify({ userName: 'insider_threat' }),
          }),
        });
        // Benign
        for (let i = 0; i < count - 2; i++) {
          events.push({
            format: 'cloudtrail', shouldTrigger: false,
            description: 'Normal IAM read operation',
            raw: cloudtrailEvent('GetUser', {
              userArn: normalUser,
              sourceIPAddress: normalIp,
              eventSource: 'iam.amazonaws.com',
              requestParameters: JSON.stringify({ userName: 'normal_user' }),
            }),
          });
        }
        break;

      case 's3_exfil':
        for (let i = 0; i < Math.floor(count * 0.7); i++) {
          events.push({
            format: 'cloudtrail', shouldTrigger: true,
            description: `Bulk download of sensitive file #${i + 1} (${(Math.random() * 50).toFixed(0)} MB)`,
            raw: cloudtrailEvent('GetObject', {
              userArn: maliciousUser,
              sourceIPAddress: suspiciousIp,
              eventSource: 's3.amazonaws.com',
              requestParameters: JSON.stringify({ bucketName: 'customer-pii', key: `records/batch_${i}.csv` }),
            }),
          });
        }
        for (let i = 0; i < Math.floor(count * 0.3); i++) {
          events.push({
            format: 'cloudtrail', shouldTrigger: false,
            description: 'Normal S3 read within expected baseline',
            raw: cloudtrailEvent('GetObject', {
              userArn: normalUser,
              sourceIPAddress: normalIp,
              eventSource: 's3.amazonaws.com',
              requestParameters: JSON.stringify({ bucketName: 'app-assets', key: `images/logo_${i}.png` }),
            }),
          });
        }
        break;

      case 'recon':
        const reconApis = ['DescribeInstances', 'ListBuckets', 'DescribeVpcs', 'ListFunctions', 'GetAccountAuthorizationDetails', 'ListRoles', 'ListUsers', 'DescribeSecurityGroups', 'ListPolicies'];
        reconApis.forEach((api, i) => {
          events.push({
            format: 'cloudtrail', shouldTrigger: i >= 5,
            description: `${api} — ${i >= 5 ? 'Excessive recon (triggers alert)' : 'Normal exploration'}`,
            raw: cloudtrailEvent(api, {
              userArn: i >= 5 ? maliciousUser : normalUser,
              sourceIPAddress: i >= 5 ? suspiciousIp : normalIp,
              eventSource: i < 3 ? 'ec2.amazonaws.com' : 'iam.amazonaws.com',
            }),
          });
        });
        break;

      default:
        // Generic events
        for (let i = 0; i < count; i++) {
          events.push({
            format: 'cloudtrail', shouldTrigger: i < count / 2,
            description: `${i < count / 2 ? 'Suspicious' : 'Benign'} ${activity} event #${i}`,
            raw: cloudtrailEvent(i < count / 2 ? 'RunInstances' : 'DescribeInstances', {
              userArn: i < count / 2 ? maliciousUser : normalUser,
              sourceIPAddress: i < count / 2 ? suspiciousIp : normalIp,
            }),
          });
        }
    }
  } else {
    // On-prem synthetic events
    switch (activity) {
      case 'delete_data':
        for (let i = 0; i < Math.floor(count * 0.7); i++) {
          events.push({
            format: 'winevent', shouldTrigger: true,
            description: `Mass file deletion — Event 4663 DELETE on sensitive file #${i}`,
            raw: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID><Computer>PROD-FS01.corp.local</Computer></System><EventData><Data Name="SubjectUserName">${maliciousUser}</Data><Data Name="ObjectName">D:\\Finance\\Q4_earnings_${i}.xlsx</Data><Data Name="AccessMask">0x10000</Data><Data Name="IpAddress">${suspiciousIp}</Data></EventData></Event>`,
          });
        }
        break;
      case 'priv_escalation':
        events.push({
          format: 'winevent', shouldTrigger: true,
          description: 'CRITICAL: User added to Domain Admins (Event 4728)',
          raw: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4728</EventID><Computer>DC01.corp.local</Computer></System><EventData><Data Name="SubjectUserName">${maliciousUser}</Data><Data Name="TargetUserName">${normalUser}</Data><Data Name="TargetSid">S-1-5-21-DOMAIN-512</Data></EventData></Event>`,
        });
        break;
      default:
        for (let i = 0; i < count; i++) {
          events.push({
            format: 'winevent', shouldTrigger: i < count / 2,
            description: `${i < count / 2 ? 'Suspicious' : 'Benign'} ${activity} Event 4688 #${i}`,
            raw: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4688</EventID><Computer>WORKSTATION-${String.fromCharCode(65 + i)}</Computer></System><EventData><Data Name="SubjectUserName">${i < count / 2 ? maliciousUser : normalUser}</Data><Data Name="NewProcessName">C:\\Windows\\System32\\${i < count / 2 ? 'cmd.exe' : 'notepad.exe'}</Data></EventData></Event>`,
          });
        }
    }
  }

  return events;
}

export function generateAllFormatExamples(): Record<string, string> {
  return {
    cloudtrail_delete: cloudtrailEvent('DeleteObject', {
      userArn: 'arn:aws:iam::123456789012:user/bad_actor',
      sourceIPAddress: '198.51.100.99',
      eventSource: 's3.amazonaws.com',
      requestParameters: JSON.stringify({ bucketName: 'prod-secrets', key: 'ssh/root_key.pem' }),
    }),
    cloudtrail_assume_role: cloudtrailEvent('AssumeRole', {
      userArn: 'arn:aws:iam::111111111111:user/compromised_user',
      sourceIPAddress: '203.0.113.254',
      eventSource: 'sts.amazonaws.com',
      requestParameters: JSON.stringify({ roleArn: 'arn:aws:iam::999999999999:role/ProductionAdmin' }),
    }),
    winevent_4663: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4663</EventID><Computer>PROD-DB.corp.local</Computer></System><EventData><Data Name="SubjectUserName">CORP\\bad_actor</Data><Data Name="ObjectName">E:\\HR\\salary_2026.xlsx</Data><Data Name="AccessMask">0x10000</Data><Data Name="IpAddress">192.168.1.99</Data></EventData></Event>`,
    winevent_4728: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4728</EventID><Computer>DC01.corp.local</Computer></System><EventData><Data Name="SubjectUserName">CORP\\bad_actor</Data><Data Name="TargetUserName">CORP\\accomplice</Data><Data Name="TargetSid">S-1-5-21-DOMAIN-512</Data></EventData></Event>`,
    edr_mimikatz: JSON.stringify({ eventType: 'ProcessRollup2', ImageFileName: 'mimikatz.exe', CommandLine: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"', UserName: 'CORP\\bad_actor', ComputerName: 'WORKSTATION-X' }),
    proxy_exfil: `192.168.1.99 - bad_actor [07/Jun/2026:03:17:00 -0400] "POST https://exfil-megaupload.xyz/upload HTTP/1.1" 200 52428800 "Mozilla/5.0" "curl/7.88"`,
  };
}
