import type { MITRETTP } from '../types';
import { ACTIVITIES } from '../data/activities';

interface RiskRoadmapProps {
  activities: string[];
  pattern: string | null;
  mitreRows: (MITRETTP & { activities: string[] })[];
}

interface RoadmapItem {
  detection: string;
  activity: string;
  riskScore: number;
  priority: string;
  rationale: string;
  impactLevel: string;
  likelihood: string;
}

const ACTIVITY_RISK_SCORES: Record<string, { impact: number; likelihood: number; priority: string }> = {
  priv_escalation:    { impact: 10, likelihood: 6, priority: 'CRITICAL' },
  credential_harvest: { impact: 10, likelihood: 7, priority: 'CRITICAL' },
  log_tamper:         { impact: 10, likelihood: 5, priority: 'CRITICAL' },
  c2_comms:           { impact: 9, likelihood: 6, priority: 'HIGH' },
  lateral_move:       { impact: 8, likelihood: 7, priority: 'HIGH' },
  delete_data:        { impact: 9, likelihood: 5, priority: 'HIGH' },
  persistence:        { impact: 8, likelihood: 7, priority: 'HIGH' },
  sensitive_access:   { impact: 7, likelihood: 6, priority: 'HIGH' },
  config_tamper:      { impact: 8, likelihood: 4, priority: 'MEDIUM' },
  s3_exfil:           { impact: 7, likelihood: 6, priority: 'MEDIUM' },
  resource_destroy:   { impact: 7, likelihood: 4, priority: 'MEDIUM' },
  backup_destroy:     { impact: 8, likelihood: 3, priority: 'MEDIUM' },
  data_stage:         { impact: 6, likelihood: 6, priority: 'MEDIUM' },
  usb_exfil:          { impact: 7, likelihood: 4, priority: 'MEDIUM' },
  secrets_access:     { impact: 7, likelihood: 5, priority: 'MEDIUM' },
  recon:              { impact: 5, likelihood: 8, priority: 'MEDIUM' },
  cross_account:      { impact: 7, likelihood: 3, priority: 'LOW' },
  repo_clone:         { impact: 6, likelihood: 4, priority: 'LOW' },
  access_revoke:      { impact: 6, likelihood: 3, priority: 'LOW' },
  resource_abuse:     { impact: 5, likelihood: 5, priority: 'LOW' },
  policy_bypass:      { impact: 6, likelihood: 3, priority: 'LOW' },
  account_create:     { impact: 5, likelihood: 4, priority: 'LOW' },
  financial_manip:    { impact: 5, likelihood: 3, priority: 'LOW' },
  logic_bomb:         { impact: 8, likelihood: 3, priority: 'MEDIUM' },
};

export function RiskRoadmap({ activities, pattern, mitreRows }: RiskRoadmapProps) {
  const actLabels: Record<string, string> = {};
  (ACTIVITIES[pattern || ''] || []).forEach((a) => { actLabels[a.val] = a.title; });

  const items: RoadmapItem[] = activities.map((act) => {
    const risk = ACTIVITY_RISK_SCORES[act] || { impact: 5, likelihood: 5, priority: 'MEDIUM' };
    const score = Math.round((risk.impact * risk.likelihood) / 10 * 10);
    return {
      detection: actLabels[act] || act,
      activity: act,
      riskScore: score,
      priority: risk.priority,
      rationale: `Impact=${risk.impact}/10, Likelihood=${risk.likelihood}/10. ${getRationale(act)}`,
      impactLevel: risk.impact >= 9 ? 'Catastrophic' : risk.impact >= 7 ? 'High' : risk.impact >= 5 ? 'Moderate' : 'Low',
      likelihood: risk.likelihood >= 8 ? 'Very Likely' : risk.likelihood >= 6 ? 'Likely' : risk.likelihood >= 4 ? 'Possible' : 'Unlikely',
    };
  });

  // Sort by risk score descending
  items.sort((a, b) => b.riskScore - a.riskScore);

  const priorityColors: Record<string, string> = {
    CRITICAL: '#ef4444',
    HIGH: '#f59e0b',
    MEDIUM: '#38bdf8',
    LOW: '#22c55e',
  };

  return (
    <div className="mitre-section" style={{ marginTop: '32px' }}>
      <div className="mitre-hd">
        <div className="mitre-hd-title">🎯 Risk-Prioritized Deployment Roadmap</div>
        <div className="mitre-hd-sub">
          {items.length} detections ranked by impact × likelihood
        </div>
      </div>
      <table className="mitre-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Detection</th>
            <th>Priority</th>
            <th>Score</th>
            <th>Impact</th>
            <th>Likelihood</th>
            <th>Deploy Order</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={item.activity}>
              <td style={{ color: 'var(--text-dim)' }}>{i + 1}</td>
              <td className="mitre-technique">{item.detection}</td>
              <td>
                <span style={{
                  fontFamily: 'var(--mono)',
                  fontSize: '9px',
                  padding: '2px 6px',
                  border: `1px solid ${priorityColors[item.priority] || '#6b7280'}22`,
                  color: priorityColors[item.priority] || '#6b7280',
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                }}>
                  {item.priority}
                </span>
              </td>
              <td style={{ color: 'var(--green)', fontWeight: 600 }}>{item.riskScore}</td>
              <td className="mitre-tactic" style={{ fontSize: '9px' }}>{item.impactLevel}</td>
              <td style={{ color: 'var(--text-mid)', fontSize: '9px' }}>{item.likelihood}</td>
              <td style={{ color: 'var(--text-dim)', fontSize: '9px' }}>
                {i === 0 ? '🥇 Deploy First' : i < 3 ? '🥈 Wave 2' : i < 6 ? '🥉 Wave 3' : `Phase ${Math.ceil((i + 1) / 3)}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function getRationale(act: string): string {
  const reasons: Record<string, string> = {
    priv_escalation: 'Privilege escalation enables all other attack vectors. Highest priority for immediate deployment.',
    credential_harvest: 'Credential theft directly enables lateral movement and data exfiltration.',
    log_tamper: 'Logging disablement blinds all other detections. Must detect immediately.',
    c2_comms: 'C2 channels indicate active compromise and likely data exfiltration in progress.',
    lateral_move: 'Lateral movement indicates an attacker is expanding their foothold.',
    delete_data: 'Mass deletion is a high-impact, irreversible action. Early detection enables backup recovery.',
    persistence: 'Persistence mechanisms ensure attacker retains access after initial compromise.',
  };
  return reasons[act] || 'Standard insider threat detection priority based on CERT/CC framework analysis.';
}
