import type { Environment, OverrideMap } from '../types';
import { AWS_LOGS, ONPREM_LOGS, AWS_REC, ONPREM_REC } from '../data/logSources';
import { OverridePanel } from './OverridePanel';

interface StepLogSourcesProps {
  env: Environment;
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  overrides: OverrideMap;
  onToggleLog: (val: string, env: 'aws' | 'onprem') => void;
  onOverride: (key: string, field: 'index' | 'sourcetype', value: string) => void;
}

export function StepLogSources({
  env, activities, awsLogs, onpremLogs, overrides, onToggleLog, onOverride,
}: StepLogSourcesProps) {
  const showAws = env === 'aws' || env === 'both';
  const showOnprem = env === 'onprem' || env === 'both';

  // Build recommended sets from selected activities
  const awsRec = new Set<string>();
  const opRec = new Set<string>();
  activities.forEach((a) => {
    (AWS_REC[a] || []).forEach((s) => awsRec.add(s));
    (ONPREM_REC[a] || []).forEach((s) => opRec.add(s));
  });

  const renderLogRow = (
    key: string,
    label: string,
    desc: string,
    indexName: string,
    rec: boolean,
    selectedLogs: string[],
    envType: 'aws' | 'onprem'
  ) => (
    <div className="log-row" key={key}>
      <div className="log-source-name">{label}</div>
      <div className="log-info">
        <div className="log-desc">{desc}</div>
        <div>
          <button
            className={`log-toggle ${selectedLogs.includes(key) ? 'selected' : ''}`}
            onClick={() => onToggleLog(key, envType)}
          >
            <span className="dot" />
            index={indexName}
          </button>
          {rec && <span className="rec-star">★ recommended</span>}
        </div>
      </div>
    </div>
  );

  return (
    <div>
      <div className="sec-head">
        <div className="sec-eyebrow">Step 4 of 5</div>
        <div className="sec-title">Configure Log Sources</div>
        <div className="sec-desc">
          Select the log sources available in your Splunk environment. Recommended sources are pre-selected.
        </div>
      </div>

      {showAws && (
        <div className="log-panel">
          <div className="log-panel-head">
            <span className="log-panel-env aws">☁ AWS Log Sources</span>
            <span className="log-panel-note">Select sources available in your Splunk environment</span>
          </div>
          {Object.entries(AWS_LOGS).map(([key, src]) =>
            renderLogRow(key, src.label, src.desc, src.index, awsRec.has(key), awsLogs, 'aws')
          )}
        </div>
      )}

      {showOnprem && (
        <div className="log-panel" style={{ marginTop: showAws ? '12px' : '0' }}>
          <div className="log-panel-head">
            <span className="log-panel-env onprem">🖥 On-Prem Log Sources</span>
            <span className="log-panel-note">Select sources available in your Splunk environment</span>
          </div>
          {Object.entries(ONPREM_LOGS).map(([key, src]) =>
            renderLogRow(key, src.label, src.desc, src.index, opRec.has(key), onpremLogs, 'onprem')
          )}
        </div>
      )}

      <OverridePanel
        env={env}
        awsRecKeys={Array.from(awsRec)}
        opRecKeys={Array.from(opRec)}
        overrides={overrides}
        onOverride={onOverride}
      />
    </div>
  );
}
