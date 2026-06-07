export type Environment = 'aws' | 'onprem' | 'both' | null;

export type Pattern = 'sabotage' | 'ip_theft' | 'fraud' | 'espionage' | 'data_manip' | 'third_party' | 'disclosure' | 'workplace' | null;

export interface Activity {
  val: string;
  icon: string;
  title: string;
  desc: string;
}

export interface LogSource {
  label: string;
  index: string;
  desc: string;
}

export interface OverrideMap {
  [key: string]: {
    index?: string;
    sourcetype?: string;
  };
}

export interface DefaultSTMap {
  [key: string]: string;
}

export interface MITRETTP {
  tid: string;
  tactic: string;
  technique: string;
  url: string;
}

export interface MITREMapType {
  [activity: string]: MITRETTP[];
}

export interface ThresholdValues {
  [key: string]: number;
}

export interface SavedConfig {
  id: string;
  name: string;
  timestamp: string;
  env: Environment;
  patterns: Pattern[];
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  overrides: OverrideMap;
}

export interface WizardState {
  env: Environment;
  patterns: Pattern[];
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  step: number;
  overrides: OverrideMap;
  thresholds: ThresholdValues;
}
