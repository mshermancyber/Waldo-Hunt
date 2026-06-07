import { generateAssetIdentityConfig, generateAssetIdentityYAML } from '../data/assetIdentity';

interface AssetIdentityConfigProps {
  activity: string;
  env: 'aws' | 'onprem';
}

export function AssetIdentityConfig({ activity, env }: AssetIdentityConfigProps) {
  const config = generateAssetIdentityConfig(env, activity);
  const yaml = generateAssetIdentityYAML(env, activity);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yaml);
  };

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">🏷 Asset & Identity Correlation</div>

      <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginBottom: '16px' }}>
        {/* Identity Fields */}
        <div style={{ flex: 1, minWidth: '280px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--blue)', marginBottom: '8px' }}>
            👤 IDENTITY FIELDS
          </div>
          <table className="mitre-table" style={{ marginBottom: 0 }}>
            <thead>
              <tr>
                <th>Field</th>
                <th>Lookup</th>
                <th>Weight</th>
              </tr>
            </thead>
            <tbody>
              {config.identityFields.map((f) => (
                <tr key={f.field}>
                  <td className="mitre-technique" style={{ fontSize: '9px' }}>{f.field}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{f.lookup}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '8px',
                      color: f.weighting === 'high' ? 'var(--red)' : f.weighting === 'medium' ? 'var(--amber)' : 'var(--text-dim)',
                    }}>
                      {f.weighting}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Asset Fields */}
        <div style={{ flex: 1, minWidth: '280px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--green)', marginBottom: '8px' }}>
            🖥 ASSET FIELDS
          </div>
          <table className="mitre-table" style={{ marginBottom: 0 }}>
            <thead>
              <tr>
                <th>Field</th>
                <th>Lookup</th>
                <th>Weight</th>
              </tr>
            </thead>
            <tbody>
              {config.assetFields.map((f) => (
                <tr key={f.field}>
                  <td className="mitre-technique" style={{ fontSize: '9px' }}>{f.field}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{f.lookup}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '8px',
                      color: f.weighting === 'high' ? 'var(--red)' : f.weighting === 'medium' ? 'var(--amber)' : 'var(--text-dim)',
                    }}>
                      {f.weighting}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: '10px' }}>
        Strategy: {config.mergeStrategy}
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
        <button className="copy-btn" onClick={handleCopy}>Copy Full YAML Config</button>
      </div>

      <pre style={{
        fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
        background: 'var(--bg)', padding: '12px', border: '1px solid var(--border)',
        lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: '400px', overflowY: 'auto',
      }}>
        {yaml}
      </pre>
    </div>
  );
}
