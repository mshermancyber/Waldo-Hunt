import { mapActorsToDetections, buildIntelGapAnalysis } from '../data/threatActors';
import type { ActorMapping, IntelGap } from '../data/threatActors';

interface ThreatActorMappingProps {
  activities: string[];
  coveredTtps: string[];
}

export function ThreatActorMapping({ activities, coveredTtps }: ThreatActorMappingProps) {
  const actorMappings = mapActorsToDetections(activities);
  const gapAnalysis = buildIntelGapAnalysis(coveredTtps);
  const coveragePercent = coveredTtps.length > 0
    ? Math.round((gapAnalysis.filter(g => g.covered).length / gapAnalysis.length) * 100)
    : 0;

  return (
    <div>
      {/* Actor Overlap */}
      <div className="mitre-section" style={{ marginTop: '32px' }}>
        <div className="mitre-hd">
          <div className="mitre-hd-title">🎯 Adversary Emulation Mapping</div>
          <div className="mitre-hd-sub">
            {actorMappings.length} threat actors mapped to your detections
          </div>
        </div>
        {actorMappings.length === 0 ? (
          <div style={{ padding: '16px', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
            No direct threat actor overlap with selected activities. Consider adding credential_harvest, lateral_move, or persistence detections for broader adversary coverage.
          </div>
        ) : (
          <table className="mitre-table">
            <thead>
              <tr>
                <th>Threat Actor</th>
                <th>Motivation</th>
                <th>Overlap</th>
                <th>Relevant Detections</th>
                <th>Linked Campaigns</th>
              </tr>
            </thead>
            <tbody>
              {actorMappings.map((m) => (
                <tr key={m.actor.id}>
                  <td>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--red)', fontWeight: 600 }}>{m.actor.name}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)' }}>{m.actor.aliases.join(', ')}</div>
                  </td>
                  <td className="mitre-tactic" style={{ fontSize: '9px' }}>{m.actor.motivation}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '9px', padding: '2px 6px',
                      border: '1px solid var(--amber-dim)', color: 'var(--amber)',
                      fontWeight: 600,
                    }}>
                      {m.relevantDetections.length} TTPs overlap
                    </span>
                  </td>
                  <td>
                    <div className="mitre-activities">
                      {m.relevantDetections.map(d => (
                        <span key={d} className="mitre-act-tag">{d.replace(/_/g, ' ')}</span>
                      ))}
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', lineHeight: 1.5 }}>
                    {m.actor.linkedCampaigns.map(c => <div key={c}>• {c}</div>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Intel Gap Analysis */}
      <div className="mitre-section" style={{ marginTop: '24px' }}>
        <div className="mitre-hd">
          <div className="mitre-hd-title">🕳 Threat Intelligence Gap Analysis</div>
          <div className="mitre-hd-sub">
            {coveragePercent}% coverage ({gapAnalysis.filter(g => g.covered).length}/{gapAnalysis.length} TTPs) against insider-relevant ATT&CK techniques
          </div>
        </div>
        <table className="mitre-table">
          <thead>
            <tr>
              <th>TTP</th>
              <th>Technique</th>
              <th>Used By</th>
              <th>Status</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {gapAnalysis.map((g) => (
              <tr key={g.technique}>
                <td>
                  <a className="mitre-link mitre-tid" href={`https://attack.mitre.org/techniques/${g.technique.replace('.', '/')}`} target="_blank" rel="noopener noreferrer">
                    {g.technique}
                  </a>
                </td>
                <td className="mitre-technique" style={{ fontSize: '10px' }}>{g.techniqueName}</td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{g.usedByActors.join(', ')}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 8px',
                    background: g.covered ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)',
                    color: g.covered ? 'var(--green)' : 'var(--red)',
                    border: `1px solid ${g.covered ? 'var(--green-dim)' : 'rgba(239,68,68,0.3)'}`,
                    letterSpacing: '0.08em',
                  }}>
                    {g.covered ? 'COVERED' : 'GAP'}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: g.covered ? 'var(--text-dim)' : 'var(--amber)', lineHeight: 1.5 }}>
                  {g.recommendedDetection}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
