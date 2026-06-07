import { useState } from 'react';
import { LOOKUP_DEFS, generateLookupCSV } from '../data/lookupCsvs';
import type { LookupCSVDef } from '../data/lookupCsvs';

export function LookupCSVGen() {
  const [selectedDef, setSelectedDef] = useState<string>(LOOKUP_DEFS[0]?.name || '');
  const def = LOOKUP_DEFS.find(d => d.name === selectedDef);
  const csv = def ? generateLookupCSV(def.name) : '';

  const handleCopy = async () => {
    if (csv) await navigator.clipboard.writeText(csv);
  };

  const handleDownload = () => {
    if (!def || !csv) return;
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = def.filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadAll = () => {
    LOOKUP_DEFS.forEach((d, i) => {
      setTimeout(() => {
        const data = generateLookupCSV(d.name);
        const blob = new Blob([data], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = d.filename;
        a.click();
        URL.revokeObjectURL(url);
      }, i * 200);
    });
  };

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">📊 Lookup CSV Generator</div>
      <div style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>Lookup Table:</span>
          <select className="override-input" value={selectedDef}
            onChange={(e) => setSelectedDef(e.target.value)}
            style={{ width: 'auto', fontSize: '10px' }}>
            {LOOKUP_DEFS.map(d => (
              <option key={d.name} value={d.name}>{d.filename}</option>
            ))}
          </select>
          <div style={{ flex: 1 }} />
          <button className="copy-btn" onClick={handleCopy} disabled={!csv}>Copy CSV</button>
          <button className="copy-btn" onClick={handleDownload} disabled={!csv}>Download</button>
          <button className="btn btn-amber" onClick={handleDownloadAll} style={{ fontSize: '9px', padding: '6px 12px' }}>
            Download All ({LOOKUP_DEFS.length})
          </button>
        </div>

        {def && (
          <div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: '10px' }}>
              {def.description}
            </div>

            {/* Column definitions */}
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--blue)', marginBottom: '6px' }}>COLUMNS</div>
              <table className="mitre-table" style={{ marginBottom: 0 }}>
                <thead>
                  <tr>
                    <th>Column</th>
                    <th>Type</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {def.columns.map(c => (
                    <tr key={c.name}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>{c.name}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)' }}>{c.type}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>{c.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Example CSV */}
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--green)', marginBottom: '6px' }}>EXAMPLE CSV</div>
              <pre style={{
                fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
                background: 'var(--bg)', padding: '12px', border: '1px solid var(--border)',
                lineHeight: 1.6, whiteSpace: 'pre', overflowX: 'auto', maxHeight: '200px', overflowY: 'auto',
              }}>
                {csv}
              </pre>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '6px' }}>
                {def.exampleRows.length} example rows included. Replace with actual data before importing into Splunk.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
