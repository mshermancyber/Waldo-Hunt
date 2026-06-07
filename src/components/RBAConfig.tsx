import { generateRBAConfig, generateRBAStanza } from '../data/rbaConfig';
import type { RBAConfig } from '../data/rbaConfig';

interface RBAConfigProps {
  activity: string;
  spl: string;
}

export function RBAConfig({ activity, spl }: RBAConfigProps) {
  const config = generateRBAConfig(activity);
  const stanza = generateRBAStanza(activity, spl);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(stanza);
  };

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">🎯 Risk-Based Alerting (RBA) Configuration</div>

      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
        <RBAField label="Risk Score" value={config.riskScore.toString()} color="var(--red)" />
        <RBAField label="Object Type" value={config.riskObject} color="var(--blue)" />
        <RBAField label="Object Field" value={config.riskObjectField} color="var(--text-bright)" />
        <RBAField label="Urgency" value={config.urgency} color={config.urgency === 'critical' ? 'var(--red)' : 'var(--amber)'} />
        <RBAField label="Priority" value={config.priority} color="var(--amber)" />
        <RBAField label="Decay" value={config.decayWindow} color="var(--text-dim)" />
        <RBAField label="Actions" value={config.alertAction} color="var(--green)" />
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
        <button className="copy-btn" onClick={handleCopy}>Copy RBA Stanza</button>
      </div>

      <pre style={{
        fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
        background: 'var(--bg)', padding: '12px', border: '1px solid var(--border)',
        lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: '400px', overflowY: 'auto',
      }}>
        {stanza}
      </pre>
    </div>
  );
}

function RBAField({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{ padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', minWidth: '110px' }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: '3px' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '11px', fontWeight: 600, color, letterSpacing: '0.04em' }}>
        {value}
      </div>
    </div>
  );
}
