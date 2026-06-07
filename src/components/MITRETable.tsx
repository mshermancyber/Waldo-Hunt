import type { MITRETTP } from '../types';

interface MITRETableProps {
  rows: (MITRETTP & { activities: string[] })[];
}

export function MITRETable({ rows }: MITRETableProps) {
  if (!rows.length) return null;

  return (
    <div className="mitre-section">
      <div className="mitre-hd">
        <div className="mitre-hd-title">MITRE ATT&CK TTP Mapping</div>
        <div className="mitre-hd-sub">
          {rows.length} techniques mapped ·{' '}
          <a className="mitre-link" href="https://attack.mitre.org" target="_blank" rel="noopener noreferrer">
            attack.mitre.org ↗
          </a>
        </div>
      </div>
      <table className="mitre-table">
        <thead>
          <tr>
            <th>Technique ID</th>
            <th>Tactic</th>
            <th>Technique</th>
            <th>Detected By</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.tid}>
              <td>
                <a className="mitre-link mitre-tid" href={r.url} target="_blank" rel="noopener noreferrer">
                  {r.tid}
                </a>
              </td>
              <td className="mitre-tactic">{r.tactic}</td>
              <td className="mitre-technique">{r.technique}</td>
              <td>
                <div className="mitre-activities">
                  {r.activities.map((a) => (
                    <span key={a} className="mitre-act-tag">{a}</span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
