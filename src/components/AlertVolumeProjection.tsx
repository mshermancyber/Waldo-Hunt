interface AlertVolumeProjectionProps {
  activities: string[];
  env: 'aws' | 'onprem' | 'both' | null;
}

// Per-activity alert volume estimates based on environment size
const ALERT_ESTIMATES: Record<string, { daily: number; fpr: number; weekly: number }> = {
  delete_data:      { daily: 3, fpr: 0.4, weekly: 21 },
  resource_destroy: { daily: 2, fpr: 0.5, weekly: 14 },
  config_tamper:    { daily: 0.5, fpr: 0.3, weekly: 4 },
  logic_bomb:       { daily: 0.1, fpr: 0.2, weekly: 1 },
  backup_destroy:   { daily: 0.3, fpr: 0.2, weekly: 2 },
  access_revoke:    { daily: 1, fpr: 0.4, weekly: 7 },
  s3_exfil:         { daily: 5, fpr: 0.7, weekly: 35 },
  repo_clone:       { daily: 1, fpr: 0.5, weekly: 7 },
  secrets_access:   { daily: 2, fpr: 0.4, weekly: 14 },
  data_stage:       { daily: 1.5, fpr: 0.5, weekly: 10 },
  cross_account:    { daily: 2, fpr: 0.5, weekly: 14 },
  usb_exfil:        { daily: 0.2, fpr: 0.3, weekly: 1 },
  priv_escalation:  { daily: 1, fpr: 0.15, weekly: 7 },
  resource_abuse:   { daily: 2, fpr: 0.6, weekly: 14 },
  policy_bypass:    { daily: 0.5, fpr: 0.3, weekly: 4 },
  account_create:   { daily: 1, fpr: 0.5, weekly: 7 },
  log_tamper:       { daily: 0.1, fpr: 0.1, weekly: 1 },
  financial_manip:  { daily: 0.3, fpr: 0.3, weekly: 2 },
  recon:            { daily: 8, fpr: 0.8, weekly: 56 },
  credential_harvest: { daily: 1, fpr: 0.2, weekly: 7 },
  sensitive_access: { daily: 2, fpr: 0.5, weekly: 14 },
  lateral_move:     { daily: 3, fpr: 0.5, weekly: 21 },
  c2_comms:         { daily: 4, fpr: 0.6, weekly: 28 },
  persistence:      { daily: 1.5, fpr: 0.4, weekly: 10 },
};

export function AlertVolumeProjection({ activities, env }: AlertVolumeProjectionProps) {
  const projections = activities.map(act => {
    const est = ALERT_ESTIMATES[act] || { daily: 2, fpr: 0.5, weekly: 14 };
    return { activity: act, ...est };
  });

  const totalDaily = projections.reduce((s, p) => s + p.daily, 0);
  const totalWeekly = projections.reduce((s, p) => s + p.weekly, 0);
  const avgFPR = projections.length > 0
    ? Math.round((projections.reduce((s, p) => s + p.fpr, 0) / projections.length) * 100)
    : 0;

  const dailyFP = Math.round(totalDaily * (avgFPR / 100));
  const dailyTP = totalDaily - dailyFP;

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">📈 Alert Volume Projection</div>

      <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginBottom: '16px' }}>
        <div style={{ flex: 1, minWidth: '120px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '32px', fontWeight: 700, color: 'var(--green)' }}>{totalDaily.toFixed(1)}</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>alerts/day</div>
        </div>
        <div style={{ flex: 1, minWidth: '120px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '32px', fontWeight: 700, color: 'var(--blue)' }}>{totalWeekly.toFixed(0)}</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>alerts/week</div>
        </div>
        <div style={{ flex: 1, minWidth: '120px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '32px', fontWeight: 700, color: 'var(--amber)' }}>{avgFPR}%</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>avg false positive rate</div>
        </div>
        <div style={{ flex: 1, minWidth: '150px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--cond)', fontSize: '24px', fontWeight: 700, color: 'var(--green)' }}>{dailyTP}</span>
            <span style={{ fontFamily: 'var(--cond)', fontSize: '24px', fontWeight: 700, color: 'var(--red)' }}>{dailyFP}</span>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>
            TP ≈ {dailyTP}/day | FP ≈ {dailyFP}/day
          </div>
        </div>
      </div>

      {/* Per-activity breakdown */}
      <table className="mitre-table" style={{ marginBottom: 0 }}>
        <thead>
          <tr>
            <th>Detection</th>
            <th>Daily Alerts</th>
            <th>Weekly</th>
            <th>FP Rate</th>
            <th>Monthly Triage Hours</th>
          </tr>
        </thead>
        <tbody>
          {projections.map((p) => {
            const monthlyHours = Math.round((p.weekly * 4 * 10) / 60 * 10) / 10; // 10 min per alert triage
            return (
              <tr key={p.activity}>
                <td className="mitre-technique" style={{ fontSize: '10px' }}>{p.activity.replace(/_/g, ' ')}</td>
                <td style={{ color: 'var(--green)', fontWeight: 600, fontSize: '11px' }}>{p.daily}</td>
                <td style={{ color: 'var(--blue)' }}>{p.weekly}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '9px',
                    color: p.fpr <= 0.3 ? 'var(--green)' : p.fpr <= 0.6 ? 'var(--amber)' : 'var(--red)',
                  }}>
                    {(p.fpr * 100).toFixed(0)}%
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
                  {monthlyHours}h
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '10px', lineHeight: 1.6 }}>
        ⚠ Estimates assume medium environment (100-500 nodes). Actual volumes depend on user behavior, baseline tuning, and exclusion quality. Multiply by 0.3 for small, 2.5 for large environments.
      </div>
    </div>
  );
}
