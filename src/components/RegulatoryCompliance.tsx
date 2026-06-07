import { getRelevantRegulations, getAllRegEntries, REGULATORY_FRAMEWORKS } from '../data/regulatoryCompliance';

interface RegulatoryComplianceProps {
  activity: string;
}

export function RegulatoryCompliance({ activity }: RegulatoryComplianceProps) {
  const relevant = getRelevantRegulations(activity);
  const allEntries = getAllRegEntries(activity);

  const frameworkColors: Record<string, string> = {
    GDPR: '#3b82f6',
    'PCI DSS': '#f59e0b',
    'ISO 27001': '#22c55e',
    HIPAA: '#8b5cf6',
    SOX: '#ef4444',
  };

  return (
    <div className="mitre-section" style={{ marginTop: '32px' }}>
      <div className="mitre-hd">
        <div className="mitre-hd-title">🏛 Regulatory Compliance Mapping</div>
        <div className="mitre-hd-sub">
          {relevant.length} frameworks applicable to {activity.replace(/_/g, ' ')}
        </div>
      </div>

      {/* Framework coverage bar */}
      <div style={{ padding: '14px 16px', display: 'flex', gap: '12px', flexWrap: 'wrap', borderBottom: '1px solid var(--border)' }}>
        {REGULATORY_FRAMEWORKS.map(fw => {
          const hasCoverage = relevant.some(r => r.name === fw.name);
          return (
            <div key={fw.name} style={{
              padding: '8px 14px', textAlign: 'center',
              border: `1px solid ${hasCoverage ? (frameworkColors[fw.name] || '#6b7280') : 'var(--border2)'}`,
              background: hasCoverage ? `${frameworkColors[fw.name] || '#6b7280'}11` : 'transparent',
              opacity: hasCoverage ? 1 : 0.4,
            }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', fontWeight: 700, color: frameworkColors[fw.name] || '#6b7280' }}>
                {fw.name}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', color: 'var(--text-dim)', marginTop: '2px' }}>
                {hasCoverage ? 'COVERED' : 'NOT APPLICABLE'}
              </div>
            </div>
          );
        })}
      </div>

      {/* All entries */}
      {allEntries.length > 0 ? (
        <table className="mitre-table" style={{ marginBottom: 0 }}>
          <thead>
            <tr>
              <th style={{ width: '60px' }}>Framework</th>
              <th style={{ width: '80px' }}>Article</th>
              <th>Requirement</th>
              <th>Coverage</th>
            </tr>
          </thead>
          <tbody>
            {allEntries.map((e, i) => (
              <tr key={i}>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 6px',
                    border: `1px solid ${(frameworkColors[e.framework] || '#6b7280')}44`,
                    color: frameworkColors[e.framework] || '#6b7280',
                    fontWeight: 700, letterSpacing: '0.06em',
                  }}>
                    {e.framework}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{e.article}</td>
                <td>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-bright)', lineHeight: 1.5 }}>{e.requirement}</div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--amber)', lineHeight: 1.4, marginTop: '4px' }}>{e.relevance}</div>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--green)', lineHeight: 1.4 }}>
                  {e.detectionCoverage}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ padding: '16px', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
          No specific regulatory mappings for this activity type. This detection contributes to general monitoring requirements across all frameworks.
        </div>
      )}
    </div>
  );
}
