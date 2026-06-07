import type { MITRETTP } from '../types';

interface CoverageMatrixProps {
  coveredTtps: string[];
  allTtps: MITRETTP[];
  selectedPatterns: string[];
}

// Full MITRE ATT&CK Enterprise tactic list for insider threat relevance
const RELEVANT_TACTICS = [
  'Collection', 'Command and Control', 'Credential Access', 'Defense Evasion',
  'Discovery', 'Execution', 'Exfiltration', 'Impact',
  'Lateral Movement', 'Persistence', 'Privilege Escalation',
];

const TACTIC_COLORS: Record<string, string> = {
  'Collection': '#7c3aed',
  'Command and Control': '#dc2626',
  'Credential Access': '#ea580c',
  'Defense Evasion': '#6b7280',
  'Discovery': '#2563eb',
  'Execution': '#059669',
  'Exfiltration': '#9333ea',
  'Impact': '#b91c1c',
  'Lateral Movement': '#0891b2',
  'Persistence': '#d97706',
  'Privilege Escalation': '#c026d3',
};

export function CoverageMatrix({ coveredTtps, allTtps, selectedPatterns }: CoverageMatrixProps) {
  // Build a map of tactic → covered TIDs
  const tacticMap: Record<string, string[]> = {};
  RELEVANT_TACTICS.forEach((t) => { tacticMap[t] = []; });

  allTtps.forEach((ttp) => {
    if (coveredTtps.includes(ttp.tid)) {
      if (!tacticMap[ttp.tactic]) tacticMap[ttp.tactic] = [];
      if (!tacticMap[ttp.tactic].includes(ttp.tid)) {
        tacticMap[ttp.tactic].push(ttp.tid);
      }
    }
  });

  const totalCovered = Object.values(tacticMap).reduce((sum, tids) => sum + tids.length, 0);
  const coveragePercent = allTtps.length > 0 ? Math.round((totalCovered / allTtps.length) * 100) : 0;

  return (
    <div className="mitre-section" style={{ marginTop: '32px' }}>
      <div className="mitre-hd">
        <div className="mitre-hd-title">⬡ MITRE ATT&CK Coverage Matrix</div>
        <div className="mitre-hd-sub">
          {totalCovered} of {allTtps.length} TTPs covered ({coveragePercent}%)
          {selectedPatterns.length > 0 && <span style={{ marginLeft: '8px' }}>· {selectedPatterns.map(p => p.replace('_', ' ')).join(', ')}</span>}
        </div>
      </div>
      <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {RELEVANT_TACTICS.map((tactic) => {
          const tids = tacticMap[tactic] || [];
          const maxTids = allTtps.filter(t => t.tactic === tactic).length;
          const pct = maxTids > 0 ? Math.round((tids.length / maxTids) * 100) : 0;
          const color = TACTIC_COLORS[tactic] || '#6b7280';

          return (
            <div key={tactic} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '140px',
                flexShrink: 0,
                fontFamily: 'var(--mono)',
                fontSize: '9px',
                letterSpacing: '0.06em',
                color: 'var(--text-mid)',
              }}>
                {tactic}
              </div>
              <div style={{
                flex: 1,
                height: '14px',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                position: 'relative',
                overflow: 'hidden',
              }}>
                <div style={{
                  width: `${pct}%`,
                  height: '100%',
                  background: color,
                  transition: 'width 0.3s ease',
                  opacity: 0.8,
                }} />
              </div>
              <div style={{
                width: '60px',
                flexShrink: 0,
                fontFamily: 'var(--mono)',
                fontSize: '9px',
                color: pct > 0 ? color : 'var(--text-dim)',
                textAlign: 'right',
              }}>
                {tids.length}/{maxTids} {pct > 0 && `(${pct}%)`}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
