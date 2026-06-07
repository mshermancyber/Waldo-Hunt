// Threat actor mapping — maps insider threat patterns to known APT groups
// and their documented TTPs from MITRE ATT&CK Groups

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  motivation: string;
  knownTtps: string[];
  linkedCampaigns: string[];
  firstSeen: string;
}

export interface ActorMapping {
  actor: ThreatActor;
  relevantDetections: string[];
  relevanceRationale: string;
}

export const THREAT_ACTORS: ThreatActor[] = [
  {
    id: 'G0007',
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Pawn Storm'],
    description: 'Russian military intelligence (GRU) threat group. Active since at least 2004. Targets government, military, and security organizations.',
    motivation: 'Espionage',
    knownTtps: ['T1003', 'T1071', 'T1078', 'T1087', 'T1098', 'T1136', 'T1550', 'T1552', 'T1562'],
    linkedCampaigns: ['2020 US Election Interference', '2016 DNC Hack', 'Operation Pawn Storm'],
    firstSeen: '2004',
  },
  {
    id: 'G0016',
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'YTTRIUM'],
    description: 'Russian Foreign Intelligence Service (SVR). Known for SolarWinds supply chain compromise. Targets government, think tanks, healthcare.',
    motivation: 'Espionage',
    knownTtps: ['T1003', 'T1021', 'T1053', 'T1071', 'T1078', 'T1098', 'T1136', 'T1190', 'T1213', 'T1485', 'T1562'],
    linkedCampaigns: ['SolarWinds 2020', 'COVID-19 Vaccine Research Theft', 'Operation Ghost'],
    firstSeen: '2008',
  },
  {
    id: 'G0045',
    name: 'APT10',
    aliases: ['Stone Panda', 'menuPass', 'POTASSIUM'],
    description: 'Chinese state-sponsored group targeting managed service providers, government, aerospace, and telecom. Known for large-scale data exfiltration.',
    motivation: 'Espionage + IP Theft',
    knownTtps: ['T1021', 'T1071', 'T1078', 'T1213', 'T1530', 'T1550', 'T1567'],
    linkedCampaigns: ['Operation Cloud Hopper', 'Operation Soft Cell'],
    firstSeen: '2009',
  },
  {
    id: 'G0114',
    name: 'Chimera',
    aliases: [],
    description: 'China-linked threat actor targeting semiconductor and tech sector. Focused on IP theft — source code, chip designs, trade secrets.',
    motivation: 'IP Theft',
    knownTtps: ['T1003', 'T1021', 'T1052', 'T1213', 'T1530', 'T1567'],
    linkedCampaigns: ['Semiconductor IP Theft Campaign 2022'],
    firstSeen: '2021',
  },
  {
    id: 'G0047',
    name: 'APT41',
    aliases: ['Winnti Group', 'BARIUM', 'Wicked Panda'],
    description: 'Chinese state-sponsored group with dual mission: espionage and financially motivated operations. Targets healthcare, telecom, tech, and gaming.',
    motivation: 'Espionage + Financial',
    knownTtps: ['T1003', 'T1021', 'T1052', 'T1053', 'T1071', 'T1078', 'T1098', 'T1136', 'T1485', 'T1490', 'T1550', 'T1562', 'T1565'],
    linkedCampaigns: ['2015 Anthem Breach', 'Gaming Industry Supply Chain', 'COVID-19 Research Theft'],
    firstSeen: '2012',
  },
];

export function mapActorsToDetections(selectedActivities: string[]): ActorMapping[] {
  const mappings: ActorMapping[] = [];

  THREAT_ACTORS.forEach((actor) => {
    const relevantDetections = selectedActivities.filter((act) => {
      // Check if this activity's MITRE TTPs overlap with the actor's known TTPs
      const activityTtps = getMitreTtpsForActivity(act);
      return activityTtps.some((ttp) => actor.knownTtps.includes(ttp));
    });

    if (relevantDetections.length > 0) {
      mappings.push({
        actor,
        relevantDetections,
        relevanceRationale: `${actor.name} is known to use ${relevantDetections.length} of your selected detection techniques. ${getRelevanceText(actor, relevantDetections)}`,
      });
    }
  });

  // Sort by number of relevant detections (most overlap first)
  mappings.sort((a, b) => b.relevantDetections.length - a.relevantDetections.length);
  return mappings;
}

function getMitreTtpsForActivity(act: string): string[] {
  const ttpMap: Record<string, string[]> = {
    credential_harvest: ['T1003', 'T1528', 'T1552', 'T1555'],
    lateral_move: ['T1550', 'T1021', 'T1078'],
    priv_escalation: ['T1078', 'T1098', 'T1136'],
    persistence: ['T1136', 'T1053', 'T1098'],
    delete_data: ['T1485', 'T1490'],
    config_tamper: ['T1562'],
    log_tamper: ['T1562', 'T1070'],
    s3_exfil: ['T1530', 'T1567'],
    repo_clone: ['T1213', 'T1530'],
    recon: ['T1087', 'T1526', 'T1580'],
    c2_comms: ['T1071', 'T1048'],
    usb_exfil: ['T1052'],
    financial_manip: ['T1565'],
    data_stage: ['T1074', 'T1020'],
    sensitive_access: ['T1213'],
    cross_account: ['T1078', 'T1550'],
    secrets_access: ['T1552', 'T1555'],
    resource_destroy: ['T1485', 'T1489'],
    backup_destroy: ['T1490', 'T1485'],
    access_revoke: ['T1531', 'T1098'],
    logic_bomb: ['T1053', 'T1485'],
    resource_abuse: ['T1496', 'T1078'],
    policy_bypass: ['T1562', 'T1484'],
    account_create: ['T1136', 'T1098'],
  };
  return ttpMap[act] || [];
}

function getRelevanceText(actor: ThreatActor, activities: string[]): string {
  const actNames = activities.map(a => a.replace(/_/g, ' ')).join(', ');
  return `Deploying detections for ${actNames} provides coverage against techniques historically used by ${actor.name} (${actor.aliases[0] || actor.id}) in campaigns like ${actor.linkedCampaigns[0]}.`;
}

// Threat intelligence gap analysis
export interface IntelGap {
  technique: string;
  techniqueName: string;
  usedByActors: string[];
  covered: boolean;
  recommendedDetection: string;
}

export function buildIntelGapAnalysis(coveredTtps: string[]): IntelGap[] {
  const insiderRelevantTtps: { tid: string; name: string; actors: string[] }[] = [
    { tid: 'T1485', name: 'Data Destruction', actors: ['APT29', 'APT41'] },
    { tid: 'T1490', name: 'Inhibit System Recovery', actors: ['APT41'] },
    { tid: 'T1562.001', name: 'Disable or Modify Tools', actors: ['APT28', 'APT29', 'APT41'] },
    { tid: 'T1562.002', name: 'Disable Windows Event Logging', actors: ['APT28', 'APT29'] },
    { tid: 'T1530', name: 'Data from Cloud Storage', actors: ['APT10', 'Chimera'] },
    { tid: 'T1567', name: 'Exfiltration Over Web Service', actors: ['APT10', 'Chimera'] },
    { tid: 'T1213', name: 'Data from Information Repositories', actors: ['APT29', 'APT10', 'Chimera'] },
    { tid: 'T1550.001', name: 'Use Alternate Authentication Material', actors: ['APT28', 'APT29', 'APT41'] },
    { tid: 'T1078', name: 'Valid Accounts', actors: ['APT28', 'APT29', 'APT10', 'APT41'] },
    { tid: 'T1098', name: 'Account Manipulation', actors: ['APT28', 'APT29', 'APT41'] },
    { tid: 'T1003', name: 'OS Credential Dumping', actors: ['APT28', 'APT29', 'Chimera', 'APT41'] },
    { tid: 'T1052.001', name: 'Exfiltration Over USB', actors: ['APT41'] },
    { tid: 'T1136', name: 'Create Account', actors: ['APT28', 'APT29', 'APT41'] },
    { tid: 'T1071', name: 'Application Layer Protocol', actors: ['APT28', 'APT29', 'APT41'] },
    { tid: 'T1053', name: 'Scheduled Task/Job', actors: ['APT29', 'APT41'] },
  ];

  return insiderRelevantTtps.map((ttp) => ({
    technique: ttp.tid,
    techniqueName: ttp.name,
    usedByActors: ttp.actors,
    covered: coveredTtps.includes(ttp.tid),
    recommendedDetection: coveredTtps.includes(ttp.tid) ? '✓ Already covered' : getRecommendedDetectionForTtp(ttp.tid),
  }));
}

function getRecommendedDetectionForTtp(tid: string): string {
  const recs: Record<string, string> = {
    'T1485': 'Deploy delete_data + resource_destroy detections',
    'T1490': 'Deploy backup_destroy + delete_data detections',
    'T1562.001': 'Deploy config_tamper + policy_bypass detections',
    'T1562.002': 'Deploy log_tamper detection',
    'T1530': 'Deploy s3_exfil + repo_clone detections',
    'T1567': 'Deploy s3_exfil + c2_comms detections',
    'T1213': 'Deploy repo_clone + sensitive_access detections',
    'T1550.001': 'Deploy lateral_move detection',
    'T1078': 'Deploy priv_escalation + lateral_move detections',
    'T1098': 'Deploy priv_escalation + persistence detections',
    'T1003': 'Deploy credential_harvest detection',
    'T1052.001': 'Deploy usb_exfil detection',
    'T1136': 'Deploy account_create + persistence detections',
    'T1071': 'Deploy c2_comms detection',
    'T1053': 'Deploy logic_bomb + persistence detections',
  };
  return recs[tid] || 'Review ATT&CK Navigator for gap coverage options';
}
