import { useState, useMemo } from 'react';
import type { SavedConfig } from '../types';

interface DetectionDiffProps {
  savedConfigs: SavedConfig[];
}

export function DetectionDiff({ savedConfigs }: DetectionDiffProps) {
  const [leftId, setLeftId] = useState<string>('');
  const [rightId, setRightId] = useState<string>('');

  const left = savedConfigs.find(c => c.id === leftId);
  const right = savedConfigs.find(c => c.id === rightId);

  // Build diff when both selected
  const diffs = useMemo(() => {
    if (!left || !right) return null;

    const changes: { field: string; left: string; right: string; changed: boolean }[] = [];

    changes.push({
      field: 'Environment',
      left: left.env || 'none',
      right: right.env || 'none',
      changed: left.env !== right.env,
    });

    changes.push({
      field: 'Patterns',
      left: left.patterns.filter(Boolean).join(', ') || 'none',
      right: right.patterns.filter(Boolean).join(', ') || 'none',
      changed: JSON.stringify(left.patterns.sort()) !== JSON.stringify(right.patterns.sort()),
    });

    changes.push({
      field: 'Activities',
      left: `${left.activities.length} selected`,
      right: `${right.activities.length} selected`,
      changed: JSON.stringify(left.activities.sort()) !== JSON.stringify(right.activities.sort()),
    });

    // Show activity-level changes
    const addedActs = right.activities.filter(a => !left.activities.includes(a));
    const removedActs = left.activities.filter(a => !right.activities.includes(a));
    if (addedActs.length || removedActs.length) {
      changes.push({
        field: 'Activity Changes',
        left: removedActs.length ? `−${removedActs.map(a => a.replace(/_/g, ' ')).join(', ')}` : 'none removed',
        right: addedActs.length ? `+${addedActs.map(a => a.replace(/_/g, ' ')).join(', ')}` : 'none added',
        changed: true,
      });
    }

    changes.push({
      field: 'AWS Log Sources',
      left: `${left.awsLogs.length} sources`,
      right: `${right.awsLogs.length} sources`,
      changed: JSON.stringify(left.awsLogs.sort()) !== JSON.stringify(right.awsLogs.sort()),
    });

    changes.push({
      field: 'On-Prem Log Sources',
      left: `${left.onpremLogs.length} sources`,
      right: `${right.onpremLogs.length} sources`,
      changed: JSON.stringify(left.onpremLogs.sort()) !== JSON.stringify(right.onpremLogs.sort()),
    });

    // Override changes
    const allKeys = new Set([...Object.keys(left.overrides), ...Object.keys(right.overrides)]);
    allKeys.forEach(key => {
      const lOv = left.overrides[key] || {};
      const rOv = right.overrides[key] || {};
      const lIdx = lOv.index || '(default)';
      const rIdx = rOv.index || '(default)';
      const lSt = lOv.sourcetype || '(default)';
      const rSt = rOv.sourcetype || '(default)';
      if (lIdx !== rIdx || lSt !== rSt) {
        changes.push({
          field: `Override: ${key}`,
          left: `index=${lIdx}, sourcetype=${lSt}`,
          right: `index=${rIdx}, sourcetype=${rSt}`,
          changed: true,
        });
      }
    });

    return changes;
  }, [left, right]);

  if (savedConfigs.length < 2) {
    return (
      <div className="override-panel">
        <div className="override-panel-hd">📊 Detection Diff View</div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)', padding: '12px' }}>
          Save at least 2 configurations to compare changes.
        </div>
      </div>
    );
  }

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">📊 Detection Diff — Compare Configurations</div>

      {/* Side-by-side selectors */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '14px' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '4px' }}>BEFORE</div>
          <select
            className="override-input"
            value={leftId}
            onChange={(e) => setLeftId(e.target.value)}
            style={{ width: '100%' }}
          >
            <option value="">Select config...</option>
            {savedConfigs.map(c => (
              <option key={c.id} value={c.id}>{c.name} ({new Date(c.timestamp).toLocaleDateString()})</option>
            ))}
          </select>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '4px' }}>AFTER</div>
          <select
            className="override-input"
            value={rightId}
            onChange={(e) => setRightId(e.target.value)}
            style={{ width: '100%' }}
          >
            <option value="">Select config...</option>
            {savedConfigs.map(c => (
              <option key={c.id} value={c.id}>{c.name} ({new Date(c.timestamp).toLocaleDateString()})</option>
            ))}
          </select>
        </div>
      </div>

      {/* Diff table */}
      {diffs && (
        <table className="mitre-table" style={{ marginBottom: 0 }}>
          <thead>
            <tr>
              <th style={{ width: '180px' }}>Field</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            {diffs.map((d, i) => (
              <tr key={i}>
                <td style={{ color: d.changed ? 'var(--amber)' : 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: '9px' }}>
                  {d.changed ? '⚠ ' : ''}{d.field}
                </td>
                <td style={{
                  fontFamily: 'var(--mono)', fontSize: '9px',
                  color: d.changed ? 'var(--red)' : 'var(--text-dim)',
                  background: d.changed ? 'rgba(239,68,68,0.06)' : 'transparent',
                }}>
                  {d.left}
                </td>
                <td style={{
                  fontFamily: 'var(--mono)', fontSize: '9px',
                  color: d.changed ? 'var(--green)' : 'var(--text-dim)',
                  background: d.changed ? 'rgba(34,197,94,0.06)' : 'transparent',
                }}>
                  {d.right}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
