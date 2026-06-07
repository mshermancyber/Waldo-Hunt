import { useState, useCallback } from 'react';
import type { Environment, Pattern, OverrideMap, ThresholdValues, SavedConfig } from '../types';
import { AWS_REC, ONPREM_REC } from '../data/logSources';

const DEFAULT_STATE = {
  env: null as Environment,
  patterns: [] as Pattern[],
  activities: [] as string[],
  awsLogs: [] as string[],
  onpremLogs: [] as string[],
  step: 0,
  overrides: {} as OverrideMap,
  thresholds: {} as ThresholdValues,
};

export function useWizardState() {
  const [state, setState] = useState(DEFAULT_STATE);

  const setEnv = useCallback((env: Environment) => {
    setState((s) => ({ ...s, env }));
  }, []);

  const togglePattern = useCallback((pattern: Pattern) => {
    setState((s) => {
      const patterns = s.patterns.includes(pattern)
        ? s.patterns.filter((p) => p !== pattern)
        : [...s.patterns, pattern];
      // Clear activities when patterns change
      return { ...s, patterns, activities: [], awsLogs: [], onpremLogs: [] };
    });
  }, []);

  const toggleActivity = useCallback((val: string) => {
    setState((s) => {
      const activities = s.activities.includes(val)
        ? s.activities.filter((a) => a !== val)
        : [...s.activities, val];
      return { ...s, activities, awsLogs: [], onpremLogs: [] };
    });
  }, []);

  const toggleLog = useCallback((val: string, env: 'aws' | 'onprem') => {
    setState((s) => {
      if (env === 'aws') {
        const awsLogs = s.awsLogs.includes(val)
          ? s.awsLogs.filter((l) => l !== val)
          : [...s.awsLogs, val];
        return { ...s, awsLogs };
      } else {
        const onpremLogs = s.onpremLogs.includes(val)
          ? s.onpremLogs.filter((l) => l !== val)
          : [...s.onpremLogs, val];
        return { ...s, onpremLogs };
      }
    });
  }, []);

  const updateOverride = useCallback((key: string, field: 'index' | 'sourcetype', value: string) => {
    setState((s) => {
      const overrides = { ...s.overrides };
      if (!overrides[key]) overrides[key] = {};
      overrides[key] = { ...overrides[key], [field]: value.trim() };
      return { ...s, overrides };
    });
  }, []);

  const updateThresholds = useCallback((thresholds: ThresholdValues) => {
    setState((s) => ({ ...s, thresholds: { ...s.thresholds, ...thresholds } }));
  }, []);

  const go = useCallback((n: number) => {
    setState((s) => ({ ...s, step: n }));
  }, []);

  const advance = useCallback(
    (from: number) => {
      if (from === 0) {
        setState((s) => ({ ...s, step: 1 }));
      } else if (from === 1) {
        setState((s) => ({ ...s, step: 2 }));
      } else if (from === 2) {
        // Auto-select recommended log sources when advancing from activities
        setState((s) => {
          const awsLogs: string[] = [];
          const onpremLogs: string[] = [];
          s.activities.forEach((a) => {
            (AWS_REC[a] || []).forEach((k) => {
              if (!awsLogs.includes(k)) awsLogs.push(k);
            });
            (ONPREM_REC[a] || []).forEach((k) => {
              if (!onpremLogs.includes(k)) onpremLogs.push(k);
            });
          });
          return { ...s, awsLogs, onpremLogs, step: 3 };
        });
      } else if (from === 3) {
        setState((s) => ({ ...s, step: 4 }));
      }
    },
    []
  );

  const resetAll = useCallback(() => {
    setState(DEFAULT_STATE);
  }, []);

  const loadConfig = useCallback((config: SavedConfig) => {
    setState((s) => ({
      ...s,
      env: config.env,
      patterns: config.patterns,
      activities: config.activities,
      awsLogs: config.awsLogs,
      onpremLogs: config.onpremLogs,
      overrides: config.overrides,
      step: 0, // start from beginning with loaded config
    }));
  }, []);

  return {
    ...state,
    setEnv,
    togglePattern,
    toggleActivity,
    toggleLog,
    updateOverride,
    updateThresholds,
    go,
    advance,
    resetAll,
    loadConfig,
  };
}
