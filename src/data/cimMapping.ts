// Splunk Common Information Model (CIM) mappings per log source
// Maps WaldoHunt log sources to CIM data models for Splunk Enterprise Security

export interface CIMMapping {
  dataModel: string;
  dataset: string;
  cimVersion: string;
  fieldMappings: Record<string, string>;
  tags: string[];
}

export const CIM_MAP: Record<string, CIMMapping> = {
  cloudtrail: {
    dataModel: 'Change_Analysis',
    dataset: 'All_Changes',
    cimVersion: '4.20',
    fieldMappings: {
      'userIdentity.arn': 'user',
      eventName: 'command',
      sourceIPAddress: 'src_ip',
      awsRegion: 'dest_zone',
      _time: '_time',
    },
    tags: ['aws', 'change', 'audit'],
  },
  s3access: {
    dataModel: 'Network_Traffic',
    dataset: 'All_Traffic',
    cimVersion: '4.20',
    fieldMappings: {
      requester: 'user',
      operation: 'action',
      bytessent: 'bytes_out',
      key: 'file_name',
      bucket: 'dest_host',
    },
    tags: ['aws', 'network', 'data-access'],
  },
  vpcflow: {
    dataModel: 'Network_Traffic',
    dataset: 'All_Traffic',
    cimVersion: '4.20',
    fieldMappings: {
      srcaddr: 'src_ip',
      dstaddr: 'dest_ip',
      srcport: 'src_port',
      dstport: 'dest_port',
      bytes: 'bytes',
      action: 'action',
    },
    tags: ['aws', 'network', 'flow'],
  },
  guardduty: {
    dataModel: 'Intrusion_Detection',
    dataset: 'IDS_Attacks',
    cimVersion: '4.20',
    fieldMappings: {
      'resource.instanceDetails.instanceId': 'dest',
      'service.action.awsApiCallAction.api': 'signature',
      severity: 'severity',
      type: 'category',
    },
    tags: ['aws', 'ids', 'threat-intel'],
  },
  iam: {
    dataModel: 'Authentication',
    dataset: 'Authentication',
    cimVersion: '4.20',
    fieldMappings: {
      userIdentity: 'user',
      eventName: 'action',
      sourceIPAddress: 'src_ip',
      'responseElements.accessKey': 'tag',
    },
    tags: ['aws', 'auth', 'identity'],
  },
  ad: {
    dataModel: 'Authentication',
    dataset: 'Authentication',
    cimVersion: '4.20',
    fieldMappings: {
      SubjectUserName: 'user',
      TargetUserName: 'dest_user',
      SubjectDomainName: 'src_domain',
      WorkstationName: 'src_host',
      EventCode: 'signature_id',
    },
    tags: ['onprem', 'windows', 'auth', 'directory'],
  },
  winsec: {
    dataModel: 'Change_Analysis',
    dataset: 'Account_Management',
    cimVersion: '4.20',
    fieldMappings: {
      SubjectUserName: 'user',
      TargetUserName: 'dest_user',
      EventCode: 'signature_id',
      ComputerName: 'dest_host',
    },
    tags: ['onprem', 'windows', 'change', 'account'],
  },
  dlp: {
    dataModel: 'Data_Access',
    dataset: 'All_Data_Access',
    cimVersion: '4.20',
    fieldMappings: {
      user_name: 'user',
      file_name: 'file_name',
      file_size: 'file_size',
      rule_name: 'policy',
      destination: 'dest',
      Severity: 'severity',
    },
    tags: ['onprem', 'dlp', 'data-exfil'],
  },
  edr: {
    dataModel: 'Endpoint',
    dataset: 'Processes',
    cimVersion: '4.20',
    fieldMappings: {
      UserName: 'user',
      ImageFileName: 'process',
      CommandLine: 'process_args',
      ComputerName: 'dest_host',
    },
    tags: ['onprem', 'endpoint', 'process', 'edr'],
  },
  proxy: {
    dataModel: 'Web',
    dataset: 'Web',
    cimVersion: '4.20',
    fieldMappings: {
      cs_username: 'user',
      c_ip: 'src_ip',
      cs_host: 'dest_host',
      cs_uri: 'uri',
      sc_bytes: 'bytes',
      cs_method: 'http_method',
    },
    tags: ['onprem', 'proxy', 'web', 'network'],
  },
};

export const CIM_TAGGING_GUIDE: Record<string, string[]> = {
  cloudtrail: ['tag::aws', 'tag::cloudtrail', 'tag::change', 'tag::audit'],
  s3access: ['tag::aws', 'tag::s3', 'tag::data_access', 'tag::network'],
  vpcflow: ['tag::aws', 'tag::vpc', 'tag::network', 'tag::flow'],
  guardduty: ['tag::aws', 'tag::guardduty', 'tag::ids', 'tag::threat'],
  iam: ['tag::aws', 'tag::iam', 'tag::auth', 'tag::identity'],
  ad: ['tag::onprem', 'tag::ad', 'tag::authentication', 'tag::windows'],
  winsec: ['tag::onprem', 'tag::windows', 'tag::security', 'tag::change'],
  dlp: ['tag::onprem', 'tag::dlp', 'tag::data_loss', 'tag::exfiltration'],
  edr: ['tag::onprem', 'tag::edr', 'tag::endpoint', 'tag::process'],
  proxy: ['tag::onprem', 'tag::proxy', 'tag::web', 'tag::network'],
};
