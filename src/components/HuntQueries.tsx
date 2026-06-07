import { getHuntQueries } from '../data/huntQueries';
import { INVESTIGATION_TIMELINES } from '../data/pivotQueries';
import { aggregateRisk } from '../data/pivotQueries';
import type { InvestigationTimeline } from '../data/pivotQueries';

interface HuntQueriesProps {
  activity: string;
  env: 'aws' | 'onprem';
}

export function HuntQueries({ activity, env }: HuntQueriesProps) {
  const hunts = getHuntQueries(activity);
  const timeline: InvestigationTimeline | undefined = INVESTIGATION_TIMELINES[activity];

  // Example aggregated risk
  const riskExample = aggregateRisk('arn:aws:iam::123456789012:user/insider', [
    { activity, riskScore: 85, severity: 'high' },
    { activity: 'lateral_move', riskScore: 75, severity: 'high' },
    { activity: 's3_exfil', riskScore: 65, severity: 'medium' },
  ]);

  return (
    <div>
      {/* Pivot Hunt Queries */}
      {hunts.length > 0 && (
        <div className="log-rec-section" style={{ marginTop: '20px' }}>
          <div className="log-rec-hd">🔎 Ad-Hoc Hunt Queries — {activity.replace(/_/g, ' ')}</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', padding: '10px 16px', lineHeight: 1.6 }}>
            When this detection fires, run these pivot searches to investigate the full scope.
          </div>

          {hunts.map((hunt, i) => (
            <div key={i} style={{
              borderTop: '1px solid var(--border)', padding: '12px 16px',
            }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)', marginBottom: '6px' }}>
                🔹 {hunt.trigger}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginBottom: '8px' }}>
                {hunt.description}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--blue)', marginBottom: '4px' }}>
                📊 {hunt.visualization}
              </div>
              <pre style={{
                fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac', lineHeight: 1.6,
                background: 'var(--bg)', padding: '10px', border: '1px solid var(--border)',
                whiteSpace: 'pre-wrap', maxHeight: '150px', overflowY: 'auto',
              }}>
                {hunt.query}
              </pre>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--green)', marginTop: '6px' }}>
                Fields: {hunt.fields.join(', ')}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Investigation Timeline */}
      {timeline && (
        <div className="log-rec-section" style={{ marginTop: '20px' }}>
          <div className="log-rec-hd">📈 Investigation Timeline Configuration</div>
          <div style={{ padding: '12px 16px' }}>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '12px' }}>
              <div style={{ padding: '8px 12px', background: 'var(--s2)', border: '1px solid var(--border)' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>X-Axis</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--green)' }}>{timeline.xField}</div>
              </div>
              <div style={{ padding: '8px 12px', background: 'var(--s2)', border: '1px solid var(--border)' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Y-Axis</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--blue)' }}>{timeline.yFields.join(', ')}</div>
              </div>
              <div style={{ padding: '8px 12px', background: 'var(--s2)', border: '1px solid var(--border)' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Split By</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--amber)' }}>{timeline.splitBy}</div>
              </div>
            </div>

            <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--green)', marginBottom: '6px' }}>ANNOTATIONS</div>
            {timeline.annotations.map((a, i) => (
              <div key={i} style={{
                fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', padding: '4px 8px',
                borderLeft: '2px solid var(--green)', marginLeft: '4px', marginBottom: '4px',
              }}>
                <strong style={{ color: 'var(--green)' }}>{a.label}:</strong>{' '}
                <span style={{ color: 'var(--text-dim)' }}>{a.search}</span>
              </div>
            ))}

            <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--blue)', marginTop: '12px', marginBottom: '6px' }}>DRILLDOWN SEARCH</div>
            <pre style={{
              fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac', lineHeight: 1.6,
              background: 'var(--bg)', padding: '10px', border: '1px solid var(--border)', whiteSpace: 'pre-wrap',
            }}>
              {timeline.drilldownSearch}
            </pre>
          </div>
        </div>
      )}

      {/* Risk Score Aggregation */}
      <div className="log-rec-section" style={{ marginTop: '20px' }}>
        <div className="log-rec-hd">📊 Compound User Risk Score</div>
        <div style={{ padding: '12px 16px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: '12px' }}>
            When multiple insider threat detections fire for the same user, compound the risk scores for a unified view.
          </div>

          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '14px' }}>
            <div style={{ flex: 1, minWidth: '140px', textAlign: 'center', padding: '12px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
              <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: riskExample.totalScore > 150 ? 'var(--red)' : 'var(--amber)' }}>
                {riskExample.totalScore}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '4px' }}>Compound Score</div>
            </div>
            <div style={{ flex: 1, minWidth: '140px', textAlign: 'center', padding: '12px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
              <div style={{ fontFamily: 'var(--cond)', fontSize: '20px', fontWeight: 700, color: 'var(--red)' }}>
                {riskExample.maxSeverity.toUpperCase()}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '4px' }}>Max Severity</div>
            </div>
            <div style={{ flex: 1, minWidth: '140px', textAlign: 'center', padding: '12px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
              <div style={{ fontFamily: 'var(--cond)', fontSize: '20px', fontWeight: 700, color: riskExample.escalationRecommended ? 'var(--red)' : 'var(--green)' }}>
                {riskExample.escalationRecommended ? '⚠ YES' : '✓ NO'}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '4px' }}>Escalate?</div>
            </div>
          </div>

          <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--amber)', marginBottom: '6px' }}>AGGREGATION SPL</div>
          <pre style={{
            fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac', lineHeight: 1.6,
            background: 'var(--bg)', padding: '10px', border: '1px solid var(--border)', whiteSpace: 'pre-wrap', maxHeight: '200px', overflowY: 'auto',
          }}>
            {`| tstats sum(risk_score) as compound_score
    values(severity) as severities
  from datamodel=Risk.All_Risk
  where risk_object_type="user"
  by risk_object
| eval max_severity=if(like(severities,"%critical%"),"CRITICAL","HIGH")
| eval escalate=if(compound_score >= 150 OR max_severity="CRITICAL","YES","NO")
| where compound_score >= 50
| sort - compound_score`}
          </pre>
        </div>
      </div>
    </div>
  );
}
