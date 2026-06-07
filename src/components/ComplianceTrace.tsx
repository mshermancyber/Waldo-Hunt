import { ACTIVITIES } from '../data/activities';
import { MITRE_MAP } from '../data/mitreMap';
import { COMPLIANCE_MAP, buildTraceability } from '../data/complianceMapping';
import type { MITRETTP } from '../types';

interface ComplianceTraceProps {
  pattern: string | null;
  activities: string[];
  mitreRows: (MITRETTP & { activities: string[] })[];
}

export function ComplianceTrace({ pattern, activities, mitreRows }: ComplianceTraceProps) {
  const patternName: Record<string, string> = {
    sabotage: 'IT Sabotage',
    ip_theft: 'IP Theft',
    fraud: 'Fraud',
    espionage: 'Espionage',
  };

  const actLabels: Record<string, string> = {};
  (ACTIVITIES[pattern || ''] || []).forEach((a) => { actLabels[a.val] = a.title; });

  if (!activities.length) return null;

  const primaryActivity = activities[0];
  const compMap = COMPLIANCE_MAP[primaryActivity] || COMPLIANCE_MAP.delete_data;

  return (
    <div className="mitre-section" style={{ marginTop: '32px' }}>
      <div className="mitre-hd">
        <div className="mitre-hd-title">🔗 Full Framework Traceability</div>
        <div className="mitre-hd-sub">
          CERT/CC → MITRE ATT&CK → NIST 800-53 → CIS Controls v8
        </div>
      </div>

      {/* Lineage row */}
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--text-dim)', marginBottom: '10px' }}>
          DETECTION LINEAGE
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <TraceBadge label="CERT/CC" value={patternName[pattern || ''] || 'Unknown'} color="var(--green)" />
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <TraceBadge label="Pattern" value={primaryActivity.replace(/_/g, ' ')} color="var(--amber)" />
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <TraceBadge label="Activity" value={actLabels[primaryActivity] || primaryActivity} color="var(--blue)" />
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <TraceBadge label="MITRE" value={mitreRows.map(r => r.tid).join(', ') || '—'} color="#f97316" />
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <TraceBadge label="NIST 800-53" value={compMap.nist80053.map(n => n.id).join(', ')} color="#8b5cf6" />
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <TraceBadge label="CIS v8" value={compMap.cis8.map(c => c.id).join(', ')} color="#06b6d4" />
        </div>
      </div>

      {/* NIST 800-53 Table */}
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: '#8b5cf6', marginBottom: '10px' }}>
          NIST 800-53 Rev 5 CONTROLS
        </div>
        <table className="mitre-table" style={{ marginBottom: 0 }}>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Title</th>
              <th>Family</th>
            </tr>
          </thead>
          <tbody>
            {compMap.nist80053.map((n) => (
              <tr key={n.id}>
                <td style={{ color: '#8b5cf6', fontWeight: 600 }}>{n.id}</td>
                <td className="mitre-technique">{n.title}</td>
                <td style={{ color: 'var(--text-mid)', fontSize: '9px' }}>{n.family}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* CIS Controls v8 Table */}
      <div style={{ padding: '16px' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: '#06b6d4', marginBottom: '10px' }}>
          CIS CONTROLS v8
        </div>
        <table className="mitre-table" style={{ marginBottom: 0 }}>
          <thead>
            <tr>
              <th>Safeguard</th>
              <th>Title</th>
              <th>Implementation Group</th>
            </tr>
          </thead>
          <tbody>
            {compMap.cis8.map((c) => (
              <tr key={c.id}>
                <td style={{ color: '#06b6d4', fontWeight: 600 }}>{c.id}</td>
                <td className="mitre-technique">{c.title}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '9px',
                    padding: '2px 6px', border: '1px solid #06b6d444',
                    color: '#06b6d4',
                  }}>
                    {c.ig}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TraceBadge({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: '2px',
      padding: '6px 10px', border: `1px solid ${color}33`,
      background: `${color}08`,
    }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
        {value}
      </div>
    </div>
  );
}
