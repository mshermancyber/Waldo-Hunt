// Baseline window guidance per detection type
// Recommended statistical baselines, lookback windows, and threshold calibration

export interface BaselineWindow {
  recommendedDays: number;
  minimumDays: number;
  statisticalMethod: string;
  thresholdGuidance: string;
  lookbackDescription: string;
  calibrationSteps: string[];
  dataVolumeEstimate: string;
}

export const BASELINE_GUIDANCE: Record<string, BaselineWindow> = {
  delete_data: {
    recommendedDays: 14,
    minimumDays: 7,
    statisticalMethod: 'mean + 3σ (standard deviation)',
    thresholdGuidance: 'Baseline daily delete_count per user. Alert threshold: > 3 standard deviations above the user\'s 14-day mean.',
    lookbackDescription: '14 days captures weekly automation cycles (CI/CD pipelines, backup rotations). Shorter windows miss periodic maintenance jobs.',
    calibrationSteps: [
      'Run the detection in report mode (no alerting) for 14 days',
      'Export daily delete_count per userIdentity.arn',
      'Calculate mean and standard deviation for each distinct user',
      'Set alert threshold at mean + 3σ for each user',
      'Review and whitelist users whose mean is above 500/day (automation roles)',
    ],
    dataVolumeEstimate: '~2-5 GB/day for CloudTrail in medium AWS environments (50-200 accounts)',
  },
  resource_destroy: {
    recommendedDays: 14,
    minimumDays: 7,
    statisticalMethod: 'mean + 2σ with minimum threshold of destroy_count > 5',
    thresholdGuidance: 'Alert when destroy_count > mean + 2σ AND destroy_count > 5 (catches bulk terminations while ignoring single-instance auto-scaling).',
    lookbackDescription: '14 days captures bi-weekly deployment cycles. 7 days is the absolute minimum.',
    calibrationSteps: [
      'Run detection in report mode for 14 days',
      'Collect destroy_count and unique_action_types per user per day',
      'Compute per-user baseline (mean, σ) for destroy_count',
      'Flag users with high mean and review whether those are expected (auto-scaling accounts)',
      'Set thresholds per user; apply a global floor of destroy_count > 5',
    ],
    dataVolumeEstimate: '~2-5 GB/day via CloudTrail',
  },
  config_tamper: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'absolute threshold (count > 2) with contextual enrichment',
    thresholdGuidance: 'Alert when count > 2 in a 24-hour window. Any StopLogging or DeleteTrail event is a CRITICAL alert regardless of count.',
    lookbackDescription: '30 days captures monthly maintenance windows and quarterly compliance audits. Config changes are infrequent.',
    calibrationSteps: [
      'Identify all known change windows (maintenance schedules)',
      'Create a whitelist of approved change initiators (automation roles, security team)',
      'Run detection in report mode for 30 days without exclusions',
      'Review all detections and classify as legitimate or suspicious',
      'Apply exclusions for known change windows and approved roles',
    ],
    dataVolumeEstimate: '~1-2 GB/day via CloudTrail (config change events are low volume)',
  },
  s3_exfil: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'per-user moving average with 10× spike detection',
    thresholdGuidance: 'Alert when download_count > 10× the user\'s 30-day moving average, OR total_gb > 5 in a single day.',
    lookbackDescription: '30 days captures monthly reporting cycles. Engineers pulling reports at month-end could appear anomalous with shorter windows.',
    calibrationSteps: [
      'Run detection in report mode for 30 days to capture monthly patterns',
      'Compute per-user 30-day moving average for download_count and total_bytes',
      'Set alert threshold at 10× individual user average',
      'Apply global floor: don\'t alert if download_count < 50 (noise floor)',
      'Whitelist data engineering roles with expected high-volume access patterns',
    ],
    dataVolumeEstimate: '~5-20 GB/day for S3 access logs in active environments',
  },
  priv_escalation: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'absolute threshold — any admin grant is critical, any non-admin count >= 2 per day',
    thresholdGuidance: 'CRITICAL: Any policy attachment containing "AdministratorAccess". HIGH: >= 2 privilege changes in a day. Review all privilege changes daily.',
    lookbackDescription: 'Privilege escalation has no safe baseline. Every event should be reviewed. 30 days provides context for frequency analysis.',
    calibrationSteps: [
      'Do NOT baseline privilege escalation — every event should be reviewed',
      'Create an allowlist of IAM admin roles for user provisioning',
      'Run detection in alert mode from day 1',
      'Tune by reviewing alerts and classifying legitimate provisioning vs. suspicious escalations',
    ],
    dataVolumeEstimate: '~1 GB/day via CloudTrail (IAM events are low volume)',
  },
  recon: {
    recommendedDays: 14,
    minimumDays: 7,
    statisticalMethod: 'per-user service diversity threshold + API count spike',
    thresholdGuidance: 'Alert when services_probed > 5 AND (api_count > 10× user average OR services_probed contains a first-time service for this user).',
    lookbackDescription: '14 days captures normal exploration patterns. New engineers will trigger this in their first week.',
    calibrationSteps: [
      'Run detection in report mode for 14 days',
      'Collect (api_count, unique_apis, services_probed) per user per day',
      'Compute per-user 14-day average for each metric',
      'Create a lookup table of never-before-accessed services per user',
      'Alert on first-time service access with > 20 API calls',
    ],
    dataVolumeEstimate: '~2-5 GB/day via CloudTrail',
  },
  credential_harvest: {
    recommendedDays: 14,
    minimumDays: 7,
    statisticalMethod: 'absolute threshold with per-secret baselines',
    thresholdGuidance: 'Alert when access_count > 10 OR unique_secrets > 3 in a 24-hour window. Any access to secrets never accessed by this user before.',
    lookbackDescription: '14 days captures normal developer secret access patterns. Some developers access many secrets daily.',
    calibrationSteps: [
      'Run detection in report mode for 14 days',
      'Collect (access_count, unique_secrets) per user per day',
      'Create per-user inventory of normally accessed secrets',
      'Alert on first-time access to any secret not in the user\'s 14-day history',
    ],
    dataVolumeEstimate: '~1-2 GB/day via CloudTrail',
  },
  lateral_move: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'first-time cross-account detection + volume threshold',
    thresholdGuidance: 'Alert when unique_accounts > 2 OR first-time AssumeRole to any target account. Cross-account count > 5 is CRITICAL.',
    lookbackDescription: '30 days captures monthly cross-account access patterns. DevOps pipeline accounts may regularly access 5-10 target accounts.',
    calibrationSteps: [
      'Run detection in report mode for 30 days',
      'Map all existing cross-account AssumeRole relationships',
      'Create a baseline of approved account-to-account trust relationships',
      'Alert on any new (never-before-seen) cross-account AssumeRole',
    ],
    dataVolumeEstimate: '~2-3 GB/day via CloudTrail',
  },
  c2_comms: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'beaconing detection + destination diversity threshold',
    thresholdGuidance: 'Alert when unique_dests > 50 OR beaconing detected (regular-interval connections to same destination > 6 hours).',
    lookbackDescription: '30 days captures normal web browsing patterns. Monthly software updates can appear anomalous with shorter windows.',
    calibrationSteps: [
      'Run detection in report mode for 30 days',
      'Collect (conn_count, unique_dests, port_diversity) per source IP per day',
      'Run beaconing detection algorithm (Fourier transform or autocorrelation on connection intervals)',
      'Create allowlist of known CDN, cloud, and software update IP ranges',
    ],
    dataVolumeEstimate: '~10-50 GB/day for VPC Flow Logs or proxy logs in active environments',
  },
  usb_exfil: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'absolute threshold — any USB write event outside IT exception list',
    thresholdGuidance: 'Alert when file_count > 20 AND user is not in the USB exception lookup. CRITICAL if file_count > 100.',
    lookbackDescription: '30 days captures infrequent USB usage patterns. USB exfiltration is rare by nature.',
    calibrationSteps: [
      'Create a lookup table of authorized USB users (IT support, AV team)',
      'Run detection in alert mode from day 1 — no baseline needed for zero-USB environments',
      'Whitelist approved device serial numbers',
      'Alert on any USB write on systems not in the exception list',
    ],
    dataVolumeEstimate: '~1-5 GB/day for Windows Event Log + EDR events',
  },
  persistence: {
    recommendedDays: 30,
    minimumDays: 14,
    statisticalMethod: 'absolute threshold with mechanism diversity alert',
    thresholdGuidance: 'Alert when count >= 2 OR mechanism_count >= 2 in 24 hours. CRITICAL if mechanism_count >= 3.',
    lookbackDescription: '30 days captures monthly maintenance tasks. Software installs and IT maintenance create scheduled tasks regularly.',
    calibrationSteps: [
      'Run detection in report mode for 30 days',
      'Categorize all detected persistence events as authorized or suspicious',
      'Create allowlist for IT maintenance tooling and approved software installers',
      'Alert on mechanism_count >= 2 from non-IT users',
    ],
    dataVolumeEstimate: '~1-3 GB/day for CloudTrail + Windows Event Logs',
  },
};
