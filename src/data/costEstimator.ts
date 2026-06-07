// Splunk license cost estimator and cost-benefit analysis
// Estimates GB/day scanned, annual license cost, and ROI per detection

export interface CostEstimate {
  gbPerDay: number;
  annualLicenseCost: number;
  splunkSvcPerDay: number;
  triageHoursPerMonth: number;
  analystCostPerMonth: number;
  totalAnnualCost: number;
  incidentCostAvoided: number;
  roiMultiplier: number;
  paybackPeriod: string;
}

interface CostParams {
  licensePerGBDay: number;    // $/GB/day annual
  analystHourlyRate: number;  // $/hr fully loaded
  avgInsiderIncidentCost: number; // Cost of one insider breach
  incidentsPerYearWithoutDetection: number; // How many you catch without this
}

const DEFAULT_PARAMS: CostParams = {
  licensePerGBDay: 250,        // ~$250/GB/day annual (Splunk list, varies by volume)
  analystHourlyRate: 85,       // $85/hr fully loaded SOC analyst
  avgInsiderIncidentCost: 500000, // $500K per insider incident (Ponemon avg)
  incidentsPerYearWithoutDetection: 0.5, // 0.5 = one every 2 years
};

// GB/day estimates per detection based on environment size and log source
const DETECTION_GB_DAY: Record<string, { small: number; medium: number; large: number }> = {
  delete_data:      { small: 0.5, medium: 3, large: 20 },
  resource_destroy: { small: 0.5, medium: 3, large: 20 },
  config_tamper:    { small: 0.3, medium: 2, large: 10 },
  logic_bomb:       { small: 0.2, medium: 1, large: 5 },
  backup_destroy:   { small: 0.3, medium: 2, large: 8 },
  access_revoke:    { small: 0.3, medium: 2, large: 8 },
  s3_exfil:         { small: 1, medium: 10, large: 50 },
  repo_clone:       { small: 0.2, medium: 1, large: 5 },
  secrets_access:   { small: 0.3, medium: 2, large: 8 },
  data_stage:       { small: 0.5, medium: 5, large: 25 },
  cross_account:    { small: 0.3, medium: 3, large: 15 },
  usb_exfil:        { small: 0.2, medium: 2, large: 10 },
  priv_escalation:  { small: 0.2, medium: 1, large: 5 },
  resource_abuse:   { small: 0.5, medium: 5, large: 25 },
  policy_bypass:    { small: 0.2, medium: 1, large: 5 },
  account_create:   { small: 0.2, medium: 1, large: 5 },
  log_tamper:       { small: 0.1, medium: 0.5, large: 3 },
  financial_manip:  { small: 0.2, medium: 1, large: 5 },
  recon:            { small: 1, medium: 8, large: 40 },
  credential_harvest:{ small: 0.2, medium: 1, large: 5 },
  sensitive_access: { small: 0.5, medium: 4, large: 20 },
  lateral_move:     { small: 0.5, medium: 5, large: 25 },
  c2_comms:         { small: 1, medium: 12, large: 60 },
  persistence:      { small: 0.3, medium: 2, large: 10 },
};

type EnvSize = 'small' | 'medium' | 'large';

export function estimateCost(
  activity: string,
  envSize: EnvSize = 'medium',
  params: Partial<CostParams> = {}
): CostEstimate {
  const p = { ...DEFAULT_PARAMS, ...params };
  const gbEstimates = DETECTION_GB_DAY[activity] || { small: 0.5, medium: 3, large: 15 };
  const gbPerDay = gbEstimates[envSize];

  // Splunk license: GB/day × annual rate
  const annualLicenseCost = gbPerDay * p.licensePerGBDay;

  // Splunk SVC: 1 SVC per 100 GB/day
  const splunkSvcPerDay = Math.ceil((gbPerDay * 1.15) / 100) * 100;

  // Triage: 10 min per alert, ~3 alerts/day × 20 working days
  const triageHoursPerMonth = Math.round((3 * 20 * 10) / 60 * 10) / 10;
  const analystCostPerMonth = triageHoursPerMonth * p.analystHourlyRate;

  // Total annual: license + analyst × 12
  const totalAnnualCost = annualLicenseCost + (analystCostPerMonth * 12);

  // Cost avoided: if this detection catches 1 insider incident every 2 years = $250K/year avoided
  const incidentCostAvoided = p.avgInsiderIncidentCost * p.incidentsPerYearWithoutDetection;

  // ROI: savings ÷ cost
  const roiMultiplier = totalAnnualCost > 0
    ? Math.round((incidentCostAvoided / totalAnnualCost) * 10) / 10
    : 999;

  // Payback: months to recover cost
  const paybackPeriod = incidentCostAvoided > 0
    ? `${Math.round((totalAnnualCost / (incidentCostAvoided / 12)) * 10) / 10} months`
    : 'N/A';

  return {
    gbPerDay: Math.round(gbPerDay * 10) / 10,
    annualLicenseCost,
    splunkSvcPerDay,
    triageHoursPerMonth,
    analystCostPerMonth: Math.round(analystCostPerMonth),
    totalAnnualCost: Math.round(totalAnnualCost),
    incidentCostAvoided,
    roiMultiplier,
    paybackPeriod,
  };
}

export function estimateBatchCost(
  activities: string[],
  envSize: EnvSize = 'medium'
): { totalGbDay: number; totalLicense: number; totalSVC: number; totalAnnual: number; perDetection: CostEstimate[] } {
  const perDetection = activities.map(a => estimateCost(a, envSize));
  const totalGbDay = perDetection.reduce((s, e) => s + e.gbPerDay, 0);
  const totalLicense = Math.round(totalGbDay * DEFAULT_PARAMS.licensePerGBDay);
  const totalSVC = Math.ceil((totalGbDay * 1.15) / 100) * 100;
  const totalAnnual = perDetection.reduce((s, e) => s + e.totalAnnualCost, 0);

  return {
    totalGbDay: Math.round(totalGbDay * 10) / 10,
    totalLicense,
    totalSVC,
    totalAnnual,
    perDetection,
  };
}

// Retention optimizer
export interface RetentionConfig {
  currentRetentionDays: number;
  requiredRetentionDays: number;
  currentDailyGB: number;
  savingsIfReducedGB: number;
  savingsIfReducedAnnual: number;
  recommendation: string;
}

export function optimizeRetention(
  activity: string,
  envSize: EnvSize = 'medium',
  currentRetentionDays: number = 90,
  requiredRetentionDays: number = 30
): RetentionConfig {
  const gbPerDay = DETECTION_GB_DAY[activity]?.[envSize] || 3;
  const excessGB = gbPerDay * (currentRetentionDays - requiredRetentionDays);
  const savingsIfReducedGB = Math.round(excessGB * 10) / 10;
  const savingsIfReducedAnnual = Math.round(excessGB * DEFAULT_PARAMS.licensePerGBDay);

  return {
    currentRetentionDays,
    requiredRetentionDays,
    currentDailyGB: Math.round(gbPerDay * 10) / 10,
    savingsIfReducedGB,
    savingsIfReducedAnnual,
    recommendation: currentRetentionDays > requiredRetentionDays
      ? `Reduce retention from ${currentRetentionDays} to ${requiredRetentionDays} days for this data source. Saves ${savingsIfReducedAnnual.toLocaleString()}/year in Splunk license costs (${savingsIfReducedGB} GB freed).`
      : `Retention is at minimum required level. No further optimization possible without impacting detection efficacy.`,
  };
}
