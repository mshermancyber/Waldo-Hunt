import { useState } from 'react';
import type { MITRETTP } from '../types';

interface SPLPanelProps {
  id: string;
  title: string;
  env: 'aws' | 'onprem';
  spl: string;
  mitre: MITRETTP[];
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function SPLPanel({ id, title, env, spl, mitre }: SPLPanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(spl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="spl-panel" style={{ marginBottom: '20px' }}>
      <div className="spl-head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <div className="spl-title">{title}</div>
          {mitre.map((t) => (
            <a
              key={t.tid}
              className="mitre-link"
              href={t.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                border: '1px solid var(--amber-dim)',
                padding: '1px 6px',
                fontSize: '8px',
                letterSpacing: '0.08em',
              }}
            >
              {t.tid}
            </a>
          ))}
        </div>
        <div className="spl-meta">
          <span className={`spl-env-tag ${env}`}>{env === 'aws' ? 'AWS' : 'On-Prem'}</span>
          <button className={`copy-btn ${copied ? 'ok' : ''}`} onClick={handleCopy}>
            {copied ? 'Copied!' : 'Copy SPL'}
          </button>
        </div>
      </div>
      <pre className="spl" id={id}>{escapeHtml(spl)}</pre>
    </div>
  );
}
