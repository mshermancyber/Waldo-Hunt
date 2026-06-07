import { useState } from 'react';
import { BASELINE_GUIDANCE } from '../data/baselineWindows';
import { CIM_MAP } from '../data/cimMapping';

interface DeploymentChecklistProps {
  activity: string;
  env: 'aws' | 'onprem';
  logKeys: string[];
}

interface ChecklistItem {
  id: string;
  phase: string;
  label: string;
  detail: string;
}

export function DeploymentChecklist({ activity, env, logKeys }: DeploymentChecklistProps) {
  const [checked, setChecked] = useState<Record<string, boolean>>({});

  const baseline = BASELINE_GUIDANCE[activity];
  const cimKeys = logKeys.filter((k) => CIM_MAP[k]);

  const items: ChecklistItem[] = [
    // Planning
    { id: 'plan-1', phase: 'Planning', label: 'Detectable events validated', detail: `Confirmed ${activity} events are being captured by ${env === 'aws' ? 'CloudTrail' : 'Windows Event Log'}` },
    { id: 'plan-2', phase: 'Planning', label: 'Data volume estimated', detail: baseline ? baseline.dataVolumeEstimate : 'Run in report mode to estimate volume' },
    { id: 'plan-3', phase: 'Planning', label: 'Lookup tables populated', detail: 'Verify sensitive_resources, internal_buckets, known_corp_domains lookups exist' },

    // Configuration
    { id: 'cfg-1', phase: 'Configuration', label: 'Index names verified', detail: 'Confirm index names match your Splunk ingestion pipeline' },
    { id: 'cfg-2', phase: 'Configuration', label: 'Sourcetypes validated', detail: 'Check sourcetype values against actual CIM mappings' },
    { id: 'cfg-3', phase: 'Configuration', label: 'CIM data model enabled', detail: cimKeys.length > 0 ? `Data models: ${cimKeys.map(k => CIM_MAP[k]?.dataModel || k).join(', ')}` : 'No CIM dependency — raw event search' },

    // Testing
    { id: 'test-1', phase: 'Testing', label: 'Run in dev search head', detail: `Execute SPL in a non-production Splunk instance for ${baseline ? baseline.recommendedDays : 14} days` },
    { id: 'test-2', phase: 'Testing', label: 'Baseline established', detail: baseline ? `Method: ${baseline.statisticalMethod}. Window: ${baseline.recommendedDays} days minimum.` : 'Run in report mode to establish baseline' },
    { id: 'test-3', phase: 'Testing', label: 'False positive review', detail: 'Classify all detections over the baseline period as legitimate or suspicious' },
    { id: 'test-4', phase: 'Testing', label: 'Thresholds calibrated', detail: 'Adjust thresholds based on baseline data before promoting to alert mode' },

    // Deployment
    { id: 'deploy-1', phase: 'Deployment', label: 'Promote to ES correlation search', detail: 'Create correlation search in Splunk ES with appropriate cron schedule' },
    { id: 'deploy-2', phase: 'Deployment', label: 'Notable event fields mapped', detail: 'Configure severity, category, description, drilldown, and next steps' },
    { id: 'deploy-3', phase: 'Deployment', label: 'Alert suppression configured', detail: 'Set throttling to prevent alert fatigue (recommended: 1h window)' },
    { id: 'deploy-4', phase: 'Deployment', label: 'Risk scoring enabled', detail: 'Wire to Splunk ES risk framework for entity scoring' },

    // Operations
    { id: 'ops-1', phase: 'Operations', label: 'Playbook published', detail: 'SOC has documented response procedures for this detection type' },
    { id: 'ops-2', phase: 'Operations', label: 'Runbook tested', detail: 'Tabletop or live-fire exercise completed for this alert scenario' },
    { id: 'ops-3', phase: 'Operations', label: 'SLA defined', detail: 'Alert acknowledged within SLA window; escalation path documented' },
  ];

  const phases = ['Planning', 'Configuration', 'Testing', 'Deployment', 'Operations'];
  const totalChecked = Object.values(checked).filter(Boolean).length;

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">
        ✅ Deployment Checklist — {activity.replace(/_/g, ' ')} ({env === 'aws' ? 'AWS' : 'On-Prem'})
        <span style={{ color: 'var(--text-dim)', marginLeft: '8px' }}>
          ({totalChecked}/{items.length})
        </span>
      </div>
      <div style={{ padding: '8px 0' }}>
        {phases.map((phase) => (
          <div key={phase} style={{ marginBottom: '12px' }}>
            <div style={{
              fontFamily: 'var(--mono)',
              fontSize: '9px',
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              color: 'var(--blue)',
              marginBottom: '6px',
              paddingLeft: '4px',
            }}>
              ▸ {phase}
            </div>
            {items.filter((i) => i.phase === phase).map((item) => (
              <div
                key={item.id}
                className="log-row"
                style={{ padding: '6px 16px', cursor: 'pointer' }}
                onClick={() => setChecked((c) => ({ ...c, [item.id]: !c[item.id] }))}
              >
                <div style={{
                  width: '16px',
                  height: '16px',
                  border: `1px solid ${checked[item.id] ? 'var(--green)' : 'var(--border2)'}`,
                  background: checked[item.id] ? 'var(--green)' : 'transparent',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '10px',
                  color: '#000',
                  flexShrink: 0,
                  marginTop: '1px',
                  transition: 'all 0.15s',
                }}>
                  {checked[item.id] ? '✓' : ''}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '9px',
                    color: checked[item.id] ? 'var(--text-mid)' : 'var(--text-bright)',
                    textDecoration: checked[item.id] ? 'line-through' : 'none',
                  }}>
                    {item.label}
                  </div>
                  <div style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '8px',
                    color: 'var(--text-dim)',
                    marginTop: '3px',
                    lineHeight: 1.4,
                  }}>
                    {item.detail}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
