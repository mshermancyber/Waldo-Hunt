import { useState } from 'react';
import { generateSigma } from '../data/sigmaTemplates';
import { generateKQL } from '../data/kqlTemplates';
import { generateCorrelationConfig, generateCorrelationYAML } from '../data/correlationDefaults';
import { generateRBAStanza } from '../data/rbaConfig';
import { generateAssetIdentityYAML } from '../data/assetIdentity';
import { generateLookupCSV } from '../data/lookupCsvs';
import { LOOKUP_DEFS } from '../data/lookupCsvs';
import { generateAccelerationYAML } from '../data/accelerationGuide';
import { ACTIVITIES } from '../data/activities';
import { MITRE_MAP } from '../data/mitreMap';
import type { Pattern } from '../types';

interface BatchExportProps {
  activities: string[];
  patterns: Pattern[];
  env: 'aws' | 'onprem' | 'both';
  splBlocks: Array<{ title: string; env: 'aws' | 'onprem'; spl: string }>;
}

export function BatchExport({ activities, patterns, env, splBlocks }: BatchExportProps) {
  const [showPreview, setShowPreview] = useState(false);
  const actLabels: Record<string, string> = {};
  patterns.forEach(p => (ACTIVITIES[p || ''] || []).forEach(a => { actLabels[a.val] = a.title; }));

  const handleDownloadAll = () => {
    // Create a JSZip-like folder structure as individual downloads
    // Since we can't do true zip in browser without library, do sequential downloads
    const delay = 200;
    downloadFile(`waldohunt-bundle/README.md`, generateReadme());

    setTimeout(() => {
      splBlocks.forEach((b, i) => {
        setTimeout(() => {
          const act = activities[i] || activities[0];
          const config = generateCorrelationConfig(act, b.title, b.spl, b.env);

          downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/correlation.yaml`, generateCorrelationYAML(config));
          downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/detection.spl`, b.spl);

          const sigmaRule = generateSigma(act, actLabels[act] || act, b.env);
          if (sigmaRule) {
            downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/sigma.json`, JSON.stringify(sigmaRule, null, 2));
          }

          const kql = generateKQL(act, actLabels[act] || act, b.env);
          if (kql) {
            downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/detection.kql`, kql.query);
          }

          downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/rba.stanza`, generateRBAStanza(act, b.spl));
          downloadFile(`waldohunt-bundle/${b.env}/${sanitizeFilename(act)}/asset_identity.yaml`, generateAssetIdentityYAML(b.env, act));
        }, i * delay);
      });
    }, delay + 100);

    // Download lookup CSVs, acceleration guide
    setTimeout(() => {
      LOOKUP_DEFS.forEach((def, i) => {
        setTimeout(() => {
          downloadFile(`waldohunt-bundle/lookups/${def.filename}`, generateLookupCSV(def.name));
        }, i * delay);
      });
      downloadFile('waldohunt-bundle/acceleration_guide.yaml', generateAccelerationYAML());
    }, splBlocks.length * delay + 200);
  };

  const generateReadme = (): string => {
    const patternNames = patterns.map(p => p?.replace('_', ' '));
    const mitreTtps = activities.flatMap(a => (MITRE_MAP[a] || []).map(t => t.tid));
    const uniqueTtps = [...new Set(mitreTtps)];

    return `# WaldoHunt Detection as Code Bundle
Generated: ${new Date().toISOString()}
Patterns: ${patternNames.join(', ')}
Activities: ${activities.length} detections
Environment: ${env.toUpperCase()}
MITRE TTPs: ${uniqueTtps.join(', ')}

## Structure
\`\`\`
waldohunt-bundle/
├── README.md              # This file
├── acceleration_guide.yaml # Data model acceleration configs
├── lookups/               # Starter CSV files for lookup tables
│   ├── sensitive_resources.csv
│   ├── internal_buckets.csv
│   ├── known_corp_domains.csv
│   ├── privileged_groups.csv
│   ├── sensitive_classifications.csv
│   └── approved_usb_devices.csv
├── aws/                   # AWS Cloud detections
│   └── <activity>/
│       ├── correlation.yaml
│       ├── detection.spl
│       ├── sigma.json
│       ├── detection.kql
│       ├── rba.stanza
│       └── asset_identity.yaml
└── onprem/                # On-Prem/Hybrid detections
    └── <activity>/
        └── ... (same structure)

## Deployment Checklist
1. Populate lookup CSVs with actual data
2. Validate SPL against your Splunk indexes
3. Import correlation.yaml into Splunk ES
4. Run in report mode for baseline period
5. Tune thresholds based on observed data
6. Promote to alert mode
`;
  };

  const totalFiles = splBlocks.length * 6 + LOOKUP_DEFS.length + 2; // per-detection files + lookups + readme + acceleration
  const fileSizes: Record<string, string> = {
    'correlation.yaml': '~2 KB',
    'detection.spl': '~1-3 KB',
    'sigma.json': '~1-2 KB',
    'detection.kql': '~1-2 KB',
    'rba.stanza': '~500 B',
    'asset_identity.yaml': '~800 B',
  };

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">📦 One-Click Batch Export</div>
      <div style={{ padding: '16px' }}>
        <div style={{ display: 'flex', gap: '12px', marginBottom: '14px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-bright)', marginBottom: '4px' }}>
              Full Deployment Package
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', lineHeight: 1.6 }}>
              {splBlocks.length} detections × 6 files + {LOOKUP_DEFS.length} lookup CSVs + acceleration guide = <strong style={{ color: 'var(--green)' }}>{totalFiles} files</strong>
            </div>
          </div>
          <button className="btn btn-amber" onClick={handleDownloadAll} style={{ fontSize: '10px', padding: '10px 20px' }}>
            ⬇ Download All ({totalFiles} files)
          </button>
        </div>

        <button className="log-toggle" onClick={() => setShowPreview(!showPreview)} style={{ marginBottom: showPreview ? '10px' : '0' }}>
          <span className="dot" />{showPreview ? 'Hide' : 'Show'} File Manifest
        </button>

        {showPreview && (
          <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', padding: '14px', maxHeight: '400px', overflowY: 'auto' }}>
            <pre style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac', lineHeight: 1.8, margin: 0, whiteSpace: 'pre-wrap' }}>
              {`waldohunt-bundle/
├── README.md
├── acceleration_guide.yaml
├── lookups/
│   ${LOOKUP_DEFS.map(d => `├── ${d.filename}`).join('\n│   ')}
${['aws', 'onprem'].map(envDir => {
  const envBlocks = splBlocks.filter(b => b.env === envDir);
  return `├── ${envDir}/
│   ${envBlocks.map(b => {
    const act = sanitizeFilename(b.title);
    return `├── ${act}/
│   │   ├── correlation.yaml
│   │   ├── detection.spl
│   │   ├── sigma.json
│   │   ├── detection.kql
│   │   ├── rba.stanza
│   │   └── asset_identity.yaml`;
  }).join('\n│   ')}`;
}).join('\n')}`}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function sanitizeFilename(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

function downloadFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
