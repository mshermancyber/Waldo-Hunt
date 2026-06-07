interface EfficacyEstimatorProps {
  activities: string[];
}

const EFFICACY_DATA: Record<string, { precision: number; recall: number; mttd: string; mtta: string }> = {
  priv_escalation:  { precision: 0.95, recall: 0.85, mttd: '< 1 min', mtta: '5 min' },
  log_tamper:       { precision: 0.98, recall: 0.90, mttd: '< 1 min', mtta: '5 min' },
  credential_harvest:{ precision: 0.90, recall: 0.75, mttd: '< 5 min', mtta: '10 min' },
  delete_data:      { precision: 0.85, recall: 0.80, mttd: '< 5 min', mtta: '15 min' },
  config_tamper:    { precision: 0.80, recall: 0.70, mttd: '< 5 min', mtta: '10 min' },
  s3_exfil:         { precision: 0.65, recall: 0.75, mttd: '< 15 min', mtta: '30 min' },
  lateral_move:     { precision: 0.80, recall: 0.75, mttd: '< 10 min', mtta: '15 min' },
  c2_comms:         { precision: 0.60, recall: 0.70, mttd: '< 15 min', mtta: '20 min' },
  recon:            { precision: 0.50, recall: 0.85, mttd: '< 30 min', mtta: '45 min' },
  persistence:      { precision: 0.75, recall: 0.70, mttd: '< 10 min', mtta: '15 min' },
  usb_exfil:        { precision: 0.90, recall: 0.70, mttd: '< 10 min', mtta: '15 min' },
};

export function EfficacyEstimator({ activities }: EfficacyEstimatorProps) {
  const scored = activities.map(act => {
    const data = EFFICACY_DATA[act] || { precision: 0.70, recall: 0.70, mttd: '< 15 min', mtta: '30 min' };
    return { activity: act, ...data };
  });

  const avgPrecision = scored.length > 0
    ? Math.round((scored.reduce((s, d) => s + d.precision, 0) / scored.length) * 100)
    : 0;
  const avgRecall = scored.length > 0
    ? Math.round((scored.reduce((s, d) => s + d.recall, 0) / scored.length) * 100)
    : 0;
  const f1Score = avgPrecision + avgRecall > 0
    ? Math.round((2 * avgPrecision * avgRecall) / (avgPrecision + avgRecall))
    : 0;

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">🎯 Detection Efficacy Estimator</div>

      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
        <div style={{ flex: 1, minWidth: '130px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: 'var(--green)' }}>{avgPrecision}%</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>Avg Precision</div>
        </div>
        <div style={{ flex: 1, minWidth: '130px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: 'var(--blue)' }}>{avgRecall}%</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>Avg Recall</div>
        </div>
        <div style={{ flex: 1, minWidth: '130px', textAlign: 'center', padding: '14px', background: 'var(--s1)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: f1Score >= 80 ? 'var(--green)' : f1Score >= 60 ? 'var(--amber)' : 'var(--red)' }}>{f1Score}%</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '4px' }}>F1 Score</div>
        </div>
      </div>

      <table className="mitre-table" style={{ marginBottom: 0 }}>
        <thead>
          <tr>
            <th>Detection</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>MTTD</th>
            <th>MTTA</th>
            <th>Detection Score</th>
          </tr>
        </thead>
        <tbody>
          {scored.map((d) => {
            const score = Math.round((d.precision * 0.5 + d.recall * 0.5) * 100);
            return (
              <tr key={d.activity}>
                <td className="mitre-technique" style={{ fontSize: '10px' }}>{d.activity.replace(/_/g, ' ')}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ flex: 1, height: '6px', background: 'var(--border)', maxWidth: '60px' }}>
                      <div style={{ width: `${d.precision * 100}%`, height: '100%', background: 'var(--green)' }} />
                    </div>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>{(d.precision * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ flex: 1, height: '6px', background: 'var(--border)', maxWidth: '60px' }}>
                      <div style={{ width: `${d.recall * 100}%`, height: '100%', background: 'var(--blue)' }} />
                    </div>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--blue)' }}>{(d.recall * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>{d.mttd}</td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)' }}>{d.mtta}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '9px', padding: '2px 8px',
                    background: score >= 85 ? 'rgba(34,197,94,0.12)' : score >= 65 ? 'rgba(245,158,11,0.12)' : 'rgba(239,68,68,0.12)',
                    color: score >= 85 ? 'var(--green)' : score >= 65 ? 'var(--amber)' : 'var(--red)',
                    border: `1px solid ${score >= 85 ? 'var(--green-dim)' : score >= 65 ? 'var(--amber-dim)' : 'rgba(239,68,68,0.3)'}`,
                    fontWeight: 600,
                  }}>
                    {score}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
