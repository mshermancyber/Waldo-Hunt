import { getAccelerationForDataModel, generateAccelerationYAML, ACCELERATION_CONFIGS } from '../data/accelerationGuide';
import { CIM_MAP } from '../data/cimMapping';

interface AccelerationGuideProps {
  logKeys: string[];
}

export function AccelerationGuide({ logKeys }: AccelerationGuideProps) {
  const yaml = generateAccelerationYAML();

  // Find which data models are relevant based on selected log sources
  const relevantModels = new Set<string>();
  logKeys.forEach(k => {
    const cim = CIM_MAP[k];
    if (cim) relevantModels.add(cim.dataModel);
  });

  const modelEntries = Object.entries(ACCELERATION_CONFIGS).filter(([name]) => relevantModels.has(name));
  const allEntries = Object.entries(ACCELERATION_CONFIGS);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yaml);
  };

  const handleDownload = () => {
    const blob = new Blob([yaml], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'splunk_acceleration_guide.yaml';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">
        ⚡ Data Model Acceleration Guide
        {logKeys.length > 0 && (
          <span style={{ color: 'var(--text-dim)', marginLeft: '8px' }}>
            ({modelEntries.length} relevant models)
          </span>
        )}
      </div>

      <div style={{ padding: '12px 16px' }}>
        {/* Relevant models (from selected log sources) */}
        {modelEntries.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--green)', marginBottom: '8px' }}>
              YOUR SELECTED SOURCES — ACCELERATION REQUIRED
            </div>
            {modelEntries.map(([name, config]) => (
              <div key={name} style={{
                padding: '10px 12px', background: 'var(--s2)', border: '1px solid var(--border)',
                marginBottom: '8px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-bright)', fontWeight: 600 }}>
                      {name}
                    </div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '2px' }}>
                      {config.dataset}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 6px',
                      border: '1px solid var(--border2)', color: 'var(--text-mid)',
                    }}>
                      {config.accelerationPeriod}
                    </span>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 6px',
                      border: '1px solid var(--green-dim)', color: 'var(--green)',
                    }}>
                      {config.cronSchedule}
                    </span>
                  </div>
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '6px', lineHeight: 1.5 }}>
                  Disk: {config.estimatedDiskGB} · Key fields: {config.keyFields.join(', ')}
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--amber)', marginTop: '4px', lineHeight: 1.4 }}>
                  {config.dependenciesNote}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* All models */}
        <div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--blue)', marginBottom: '8px' }}>
            ALL DATA MODELS (for reference)
          </div>
          <table className="mitre-table" style={{ marginBottom: 0 }}>
            <thead>
              <tr>
                <th>Data Model</th>
                <th>Dataset</th>
                <th>Summary</th>
                <th>Cron</th>
                <th>Est. Disk</th>
              </tr>
            </thead>
            <tbody>
              {allEntries.map(([name, config]) => (
                <tr key={name} style={{
                  background: relevantModels.has(name) ? 'rgba(34,197,94,0.04)' : 'transparent',
                }}>
                  <td className="mitre-technique" style={{ fontSize: '10px' }}>
                    {relevantModels.has(name) ? '▸ ' : ''}{name}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{config.dataset}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>{config.summaryRange}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)' }}>{config.cronSchedule}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)' }}>{config.estimatedDiskGB}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', gap: '8px', marginTop: '14px' }}>
          <button className="copy-btn" onClick={handleCopy}>Copy Full YAML</button>
          <button className="copy-btn" onClick={handleDownload}>Download .yaml</button>
        </div>
      </div>
    </div>
  );
}
