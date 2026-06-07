import { useState } from 'react';
import type { Environment, Pattern, OverrideMap, MITRETTP } from '../types';
import { ACTIVITIES } from '../data/activities';
import { AWS_LOGS, ONPREM_LOGS, AWS_REC, ONPREM_REC, DEFAULT_ST } from '../data/logSources';
import { AWS_SPL, ONPREM_SPL } from '../data/splTemplates';
import { MITRE_MAP } from '../data/mitreMap';
import { FP_GUIDANCE } from '../data/fpGuidance';
import { BASELINE_GUIDANCE } from '../data/baselineWindows';
import { CIM_TAGGING_GUIDE } from '../data/cimMapping';
import { COMPLIANCE_MAP } from '../data/complianceMapping';
import { SPLPanel } from './SPLPanel';
import { MITRETable } from './MITRETable';
import { CoverageMatrix } from './CoverageMatrix';
import { ExportPanel } from './ExportPanel';
import { DeploymentChecklist } from './DeploymentChecklist';
import { DetectionPlaybook } from './DetectionPlaybook';
import { ComplianceTrace } from './ComplianceTrace';
import { RiskRoadmap } from './RiskRoadmap';
import { SavedConfigs } from './SavedConfigs';
import { VolumeEstimator } from './VolumeEstimator';
import { SyntheticEventGen } from './SyntheticEventGen';
import { AlertVolumeProjection } from './AlertVolumeProjection';
import { EfficacyEstimator } from './EfficacyEstimator';
import { ThreatActorMapping } from './ThreatActorMapping';
import { CampaignBundles } from './CampaignBundles';
import { SuppressionBuilder } from './SuppressionBuilder';
import { RBAConfig } from './RBAConfig';
import { AssetIdentityConfig } from './AssetIdentityConfig';
import { LookupCSVGen } from './LookupCSVGen';
import { AccelerationGuide } from './AccelerationGuide';
import { MarkdownBrief } from './MarkdownBrief';
import { PeerReview } from './PeerReview';
import { BatchExport } from './BatchExport';
import { CICDPipeline } from './CICDPipeline';
import { DetectionDiff } from './DetectionDiff';
import { HuntQueries } from './HuntQueries';
import { MultiPlatformExport } from './MultiPlatformExport';
import { IncidentTemplates } from './IncidentTemplates';
import { RegulatoryCompliance } from './RegulatoryCompliance';
import { CostEstimator } from './CostEstimator';

interface StepOutputProps {
  env: Environment;
  patterns: Pattern[];
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  overrides: OverrideMap;
  onLoad: (c: import('../types').SavedConfig) => void;
}

const ENV_LABEL: Record<string, string> = { aws: 'AWS Cloud', onprem: 'On-Prem / Hybrid', both: 'Hybrid (AWS + On-Prem)' };
const PAT_LABEL: Record<string, string> = { sabotage: 'IT Sabotage', ip_theft: 'IP Theft', fraud: 'Fraud', espionage: 'Espionage' };

const STORAGE_KEY = 'waldohunt-configs';

function safeLoadDiffConfigs(): import('../types').SavedConfig[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((c: unknown): c is import('../types').SavedConfig => {
      if (!c || typeof c !== 'object') return false;
      const cfg = c as Record<string, unknown>;
      return typeof cfg.id === 'string' && typeof cfg.name === 'string' && Array.isArray(cfg.activities);
    }).slice(0, 20);
  } catch { return []; }
}

type OutputTab = 'spl' | 'testing' | 'hunt' | 'intel' | 'coverage' | 'roadmap' | 'cost' | 'compliance' | 'export' | 'platforms' | 'tickets' | 'deploy' | 'checklist' | 'playbook' | 'operations' | 'trace';

function primaryLogKey(act: string, env: 'aws' | 'onprem'): string | null {
  const rec = env === 'aws' ? (AWS_REC[act] || []) : (ONPREM_REC[act] || []);
  return rec[0] || null;
}

function applyOverrides(spl: string, logKey: string | null, overrides: OverrideMap): string {
  if (!logKey) return spl;
  const src = AWS_LOGS[logKey] || ONPREM_LOGS[logKey];
  if (!src) return spl;
  const ov = overrides[logKey] || {};
  const defIdx = src.index;
  const defSt = DEFAULT_ST[logKey] || '';
  const newIdx = ov.index || defIdx;
  const newSt = ov.sourcetype || defSt;
  let out = spl;
  if (newIdx !== defIdx) {
    const idxPattern = defIdx.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(`index=${idxPattern}`, 'g'), () => `index=${newIdx}`);
  }
  if (defSt && newSt !== defSt) {
    const stPattern = defSt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(stPattern, 'g'), () => newSt);
  }
  return out;
}

function buildMitreRows(selectedActivities: string[], allPatterns: Pattern[]): (MITRETTP & { activities: string[] })[] {
  const seen = new Set<string>();
  const rows: (MITRETTP & { activities: string[] })[] = [];
  selectedActivities.forEach((act) => {
    const ttps = MITRE_MAP[act] || [];
    const actLabel = allPatterns.flatMap(p => ACTIVITIES[p || ''] || []).find(a => a.val === act)?.title || act;
    ttps.forEach((t) => {
      if (!seen.has(t.tid)) { seen.add(t.tid); rows.push({ ...t, activities: [actLabel] }); }
      else { const existing = rows.find(r => r.tid === t.tid); if (existing && !existing.activities.includes(actLabel)) existing.activities.push(actLabel); }
    });
  });
  return rows;
}

function getAllTtps(allPatterns: Pattern[], activities: string[]): MITRETTP[] {
  const seen = new Set<string>();
  const result: MITRETTP[] = [];
  activities.forEach(act => {
    (MITRE_MAP[act] || []).forEach(t => { if (!seen.has(t.tid)) { seen.add(t.tid); result.push(t); } });
  });
  return result;
}

export function StepOutput({ env, patterns, activities, awsLogs, onpremLogs, overrides, onLoad }: StepOutputProps) {
  const [tab, setTab] = useState<OutputTab>('spl');

  if (!env || !patterns.length) return null;

  const showAws = env === 'aws' || env === 'both';
  const showOnprem = env === 'onprem' || env === 'both';
  const allActivities = patterns.flatMap(p => ACTIVITIES[p || ''] || []);

  const actLabels: Record<string, string> = {};
  allActivities.forEach(a => { actLabels[a.val] = a.title; });

  const splBlocks: Array<{ id: string; title: string; env: 'aws' | 'onprem'; spl: string; mitre: MITRETTP[] }> = [];
  let blockIdx = 0;

  activities.forEach((act) => {
    const title = actLabels[act] || act;
    if (showAws && AWS_SPL[act]) {
      const logKey = primaryLogKey(act, 'aws');
      const spl = applyOverrides(AWS_SPL[act](), logKey, overrides);
      const mitre = (MITRE_MAP[act] || []).slice(0, 2);
      splBlocks.push({ id: `spl-${blockIdx++}`, title, env: 'aws', spl, mitre });
    }
    if (showOnprem && ONPREM_SPL[act]) {
      const logKey = primaryLogKey(act, 'onprem');
      const spl = applyOverrides(ONPREM_SPL[act](), logKey, overrides);
      const mitre = (MITRE_MAP[act] || []).slice(0, 2);
      splBlocks.push({ id: `spl-${blockIdx++}`, title, env: 'onprem', spl, mitre });
    }
  });

  const mitreRows = buildMitreRows(activities, patterns);
  const allTtps = getAllTtps(patterns, activities);
  const coveredTtpIds = allTtps.map(t => t.tid);

  const buildRecRow = (key: string, label: string, desc: string, indexName: string, st: string) => {
    const ov = overrides[key] || {};
    const idx = ov.index || indexName;
    const sourcetype = ov.sourcetype || st;
    return (
      <div className="log-rec-row" key={key}>
        <div><div className="log-rec-name">{label}</div><div className="log-rec-index">index={idx}{sourcetype ? ' · ' + sourcetype : ''}</div></div>
        <div className="log-rec-desc">{desc}</div>
      </div>
    );
  };

  const tabs: { val: OutputTab; label: string; count?: string }[] = [
    { val: 'spl', label: 'SPL', count: `${splBlocks.length}` },
    { val: 'testing', label: 'Testing' },
    { val: 'hunt', label: 'Hunt' },
    { val: 'intel', label: 'Intel' },
    { val: 'coverage', label: 'Coverage', count: `${coveredTtpIds.length}` },
    { val: 'roadmap', label: 'Roadmap' },
    { val: 'cost', label: 'Cost' },
    { val: 'compliance', label: 'Compliance' },
    { val: 'export', label: 'Export' },
    { val: 'platforms', label: 'Platforms' },
    { val: 'tickets', label: 'Tickets' },
    { val: 'deploy', label: 'Deploy' },
    { val: 'checklist', label: 'Checklist' },
    { val: 'playbook', label: 'Playbook' },
    { val: 'operations', label: 'Ops' },
    { val: 'trace', label: 'Trace' },
  ];

  return (
    <div>
      <div className="sec-head">
        <div className="sec-eyebrow">Step 5 of 5</div>
        <div className="sec-title">Detection Output</div>
      </div>

      <div className="summary-row">
        <div className="sum-pill">Environment: <span>{ENV_LABEL[env]}</span></div>
        <div className="sum-pill">Patterns: <span>{patterns.map(p => p?.replace('_', ' ') || '').join(', ')}</span></div>
        <div className="sum-pill">Activities: <span>{activities.length}</span></div>
        <div className="sum-pill">AWS Sources: <span>{awsLogs.length}</span></div>
        <div className="sum-pill">On-Prem Sources: <span>{onpremLogs.length}</span></div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '20px', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
        {tabs.map(t => (
          <button key={t.val}
            className={`log-toggle ${tab === t.val ? 'selected' : ''}`}
            onClick={() => setTab(t.val)}
          >
            <span className="dot" />
            {t.label}
            {t.count && <span style={{ color: tab === t.val ? 'var(--green)' : 'var(--text-dim)', marginLeft: '4px' }}>({t.count})</span>}
          </button>
        ))}
      </div>

      {/* SPL Tab */}
      {tab === 'spl' && (
        <div>
          <div className="log-rec-section">
            <div className="log-rec-hd">📋 Ingestion Requirements</div>
            {showAws && awsLogs.map(k => { const s = AWS_LOGS[k]; if (!s) return null; return buildRecRow(k, s.label, s.desc, s.index, DEFAULT_ST[k] || ''); })}
            {showOnprem && onpremLogs.map(k => { const s = ONPREM_LOGS[k]; if (!s) return null; return buildRecRow(k, s.label, s.desc, s.index, DEFAULT_ST[k] || ''); })}
          </div>
          <VolumeEstimator selectedAwsLogs={awsLogs} selectedOnpremLogs={onpremLogs} env={env} />
          <SavedConfigs env={env} patterns={patterns} activities={activities} awsLogs={awsLogs} onpremLogs={onpremLogs} overrides={overrides} onLoad={onLoad} />
          {splBlocks.map((block, i) => {
            const prevBlock = i > 0 ? splBlocks[i - 1] : null;
            const showHeader = !prevBlock || prevBlock.env !== block.env;
            return (
              <div key={block.id}>
                {showHeader && (
                  <div className="env-section-label" style={{ marginTop: i === 0 ? '16px' : '24px' }}>
                    <div className="env-section-line" />
                    <div className={`env-section-text ${block.env}`}>{block.env === 'aws' ? '☁ AWS Cloud' : '🖥 On-Prem / Hybrid'}</div>
                    <div className="env-section-line" />
                  </div>
                )}
                <SPLPanel id={block.id} title={block.title} env={block.env} spl={block.spl} mitre={block.mitre} />
              </div>
            );
          })}
          <MITRETable rows={mitreRows} />
          <div className="warn-panel">⚠ <strong>Tuning Notes:</strong> These SPL queries are starting points. Validate index names and sourcetype values against your Splunk ingestion pipeline. Test in a non-production search head before promoting to correlation searches.</div>
        </div>
      )}

      {/* Testing Tab */}
      {tab === 'testing' && activities.length > 0 && (
        <div>
          <SyntheticEventGen activity={activities[0]} env={showAws ? 'aws' : 'onprem'} />
          <EfficacyEstimator activities={activities} />
          <AlertVolumeProjection activities={activities} env={env} />
        </div>
      )}

      {/* Hunt Tab */}
      {tab === 'hunt' && activities.length > 0 && (
        <HuntQueries activity={activities[0]} env={showAws ? 'aws' : 'onprem'} />
      )}

      {/* Intel Tab */}
      {tab === 'intel' && (
        <div>
          <CampaignBundles
            selectedPatterns={patterns.filter((p) => p != null) as string[]}
            selectedActivities={activities}
            onApplyBundle={(_bundle) => {}}
          />
          <ThreatActorMapping activities={activities} coveredTtps={coveredTtpIds} />
        </div>
      )}

      {/* Coverage Tab */}
      {tab === 'coverage' && (
        <div>
          <CoverageMatrix coveredTtps={coveredTtpIds} allTtps={allTtps} selectedPatterns={patterns.map(p => p ? PAT_LABEL[p] : '')} />
          <MITRETable rows={mitreRows} />
        </div>
      )}

      {/* Roadmap Tab */}
      {tab === 'roadmap' && (
        <div>
          <RiskRoadmap activities={activities} pattern={patterns[0]} mitreRows={mitreRows} />
          <MITRETable rows={mitreRows} />
        </div>
      )}

      {/* Cost Tab */}
      {tab === 'cost' && <CostEstimator activities={activities} />}

      {/* Compliance Tab */}
      {tab === 'compliance' && activities.length > 0 && <RegulatoryCompliance activity={activities[0]} />}

      {/* Export Tab */}
      {tab === 'export' && (
        <ExportPanel activities={activities} pattern={patterns[0]} env={env === 'both' ? 'both' : showAws ? 'aws' : 'onprem'} splBlocks={splBlocks.map(b => ({ title: b.title, env: b.env, spl: b.spl }))} />
      )}

      {/* Platforms Tab */}
      {tab === 'platforms' && (
        <MultiPlatformExport activities={activities} patterns={patterns} env={env === 'both' ? 'both' : showAws ? 'aws' : 'onprem'} />
      )}

      {/* Tickets Tab */}
      {tab === 'tickets' && activities.length > 0 && (
        <IncidentTemplates activity={activities[0]} env={env === 'both' ? 'both' : showAws ? 'aws' : 'onprem'} patterns={patterns} />
      )}

      {/* Deploy Tab */}
      {tab === 'deploy' && (
        <div>
          <BatchExport activities={activities} patterns={patterns} env={env === 'both' ? 'both' : showAws ? 'aws' : 'onprem'} splBlocks={splBlocks.map(b => ({ title: b.title, env: b.env, spl: b.spl }))} />
          <CICDPipeline activities={activities} splBlocks={splBlocks.map(b => ({ title: b.title, env: b.env, spl: b.spl }))} />
          <AccelerationGuide logKeys={[...awsLogs, ...onpremLogs]} />
          <LookupCSVGen />
          {activities.length > 0 && (
            <>
              <AssetIdentityConfig activity={activities[0]} env={showAws ? 'aws' : 'onprem'} />
              <MarkdownBrief activity={activities[0]} pattern={patterns[0]} env={env === 'both' ? 'both' : showAws ? 'aws' : 'onprem'} />
            </>
          )}
        </div>
      )}

      {/* Checklist Tab */}
      {tab === 'checklist' && activities.length > 0 && (
        <div>
          <DeploymentChecklist activity={activities[0]} env={showAws ? 'aws' : 'onprem'} logKeys={[...awsLogs, ...onpremLogs]} />
          {activities.slice(1).map(act => (
            <DeploymentChecklist key={act} activity={act} env={showAws ? 'aws' : 'onprem'} logKeys={[...awsLogs, ...onpremLogs]} />
          ))}
        </div>
      )}

      {/* Playbook Tab */}
      {tab === 'playbook' && activities.length > 0 && (
        <div>
          <DetectionPlaybook activity={activities[0]} />
          {activities.slice(1).map(act => <DetectionPlaybook key={act} activity={act} />)}
        </div>
      )}

      {/* Operations Tab */}
      {tab === 'operations' && activities.length > 0 && (
        <div>
          <RBAConfig activity={activities[0]} spl={splBlocks[0]?.spl || ''} />
          <SuppressionBuilder activity={activities[0]} env={showAws ? 'aws' : 'onprem'} />
          <PeerReview activity={activities[0]} />
          <DetectionDiff savedConfigs={safeLoadDiffConfigs()} />
        </div>
      )}

      {/* Trace Tab */}
      {tab === 'trace' && (
        <div>
          <ComplianceTrace pattern={patterns[0]} activities={activities} mitreRows={mitreRows} />
          <div className="log-rec-section" style={{ marginTop: '24px' }}>
            <div className="log-rec-hd">🏷 CIM Tagging Guide</div>
            <table className="mitre-table" style={{ marginBottom: 0 }}>
              <thead><tr><th>Log Source</th><th>Splunk Tags</th></tr></thead>
              <tbody>
                {[...awsLogs, ...onpremLogs].map(k => {
                  const tags = CIM_TAGGING_GUIDE[k];
                  return (
                    <tr key={k}>
                      <td className="mitre-technique">{k}</td>
                      <td><div className="mitre-activities">{(tags || []).map(t => <span key={t} className="mitre-act-tag">{t}</span>)}</div></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {activities.length > 0 && FP_GUIDANCE[activities[0]] && (
            <div className="log-rec-section" style={{ marginTop: '24px' }}>
              <div className="log-rec-hd">🎯 False Positive Guidance — {activities[0].replace(/_/g, ' ')}</div>
              <div style={{ padding: '12px 4px' }}>
                <div style={{ display: 'flex', gap: '12px', marginBottom: '14px', flexWrap: 'wrap' }}>
                  <FPStat label="Noise Level" value={FP_GUIDANCE[activities[0]].noiseLevel.toUpperCase()} color={FP_GUIDANCE[activities[0]].noiseLevel === 'low' ? 'var(--green)' : 'var(--amber)'} />
                  <FPStat label="Expected Baseline" value={FP_GUIDANCE[activities[0]].expectedBaseline} color="var(--text-bright)" />
                </div>
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.08em', color: 'var(--amber)', marginBottom: '6px' }}>Common FP Scenarios</div>
                  {FP_GUIDANCE[activities[0]].commonScenarios.map((s, i) => (
                    <div key={i} style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', lineHeight: 1.6, paddingLeft: '12px', marginBottom: '4px' }}>• {s}</div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activities.length > 0 && BASELINE_GUIDANCE[activities[0]] && (
            <BaselineSection activity={activities[0]} />
          )}
        </div>
      )}
    </div>
  );
}

function FPStat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{ padding: '8px 12px', background: 'var(--s2)', border: '1px solid var(--border)' }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '2px' }}>{label}</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color, fontWeight: 600 }}>{value}</div>
    </div>
  );
}

function BaselineSection({ activity }: { activity: string }) {
  const b = BASELINE_GUIDANCE[activity];
  if (!b) return null;
  return (
    <div className="log-rec-section" style={{ marginTop: '24px' }}>
      <div className="log-rec-hd">📈 Baseline Window Guidance — {activity.replace(/_/g, ' ')}</div>
      <div style={{ padding: '12px 4px' }}>
        <div style={{ display: 'flex', gap: '12px', marginBottom: '14px', flexWrap: 'wrap' }}>
          <FPStat label="Recommended" value={`${b.recommendedDays} days`} color="var(--green)" />
          <FPStat label="Method" value={b.statisticalMethod} color="var(--text-bright)" />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.08em', color: 'var(--blue)', marginBottom: '6px' }}>Calibration Steps</div>
          {b.calibrationSteps.map((s, i) => (
            <div key={i} style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', lineHeight: 1.6, paddingLeft: '12px', marginBottom: '4px' }}>{i + 1}. {s}</div>
          ))}
        </div>
      </div>
    </div>
  );
}
