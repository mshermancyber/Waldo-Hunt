import { useState, useMemo } from 'react';
import { generateSyntheticEvents, generateAllFormatExamples, type SyntheticEvent } from '../data/syntheticEvents';
import { getTestForActivity, getExpectedOutputSample, type TestAssertion } from '../data/unitTestAssertions';

interface SyntheticEventGenProps {
  activity: string;
  env: 'aws' | 'onprem';
}

export function SyntheticEventGen({ activity, env }: SyntheticEventGenProps) {
  const [eventCount, setEventCount] = useState(10);
  const [showExamples, setShowExamples] = useState(false);

  const events = useMemo(() => generateSyntheticEvents(activity, env, eventCount), [activity, env, eventCount]);
  const assertions = useMemo(() => getTestForActivity(activity, env), [activity, env]);
  const expectedOutput = useMemo(() => getExpectedOutputSample(activity, env), [activity, env]);
  const formatExamples = useMemo(() => generateAllFormatExamples(), []);

  const triggerCount = events.filter((e) => e.shouldTrigger).length;
  const benignCount = events.filter((e) => !e.shouldTrigger).length;

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">
        🧪 Synthetic Event Generator — {activity.replace(/_/g, ' ')} ({env.toUpperCase()})
      </div>

      {/* Event count control */}
      <div style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '12px', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          Events:
        </span>
        <input type="range" min={5} max={50} value={eventCount} onChange={(e) => setEventCount(parseInt(e.target.value))}
          style={{ accentColor: 'var(--green)', flex: 1, maxWidth: '200px' }} />
        <span style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--green)', fontWeight: 600 }}>{eventCount}</span>
        <div style={{ flex: 1 }} />
        <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--red)' }}>🔴 {triggerCount} triggers</span>
        <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>🟢 {benignCount} benign</span>
      </div>

      {/* Generated events */}
      <div style={{ maxHeight: '400px', overflowY: 'auto', fontFamily: 'var(--mono)', fontSize: '9px' }}>
        {events.map((e, i) => (
          <div key={i} style={{
            padding: '8px 14px', borderBottom: '1px solid var(--border)',
            borderLeft: `3px solid ${e.shouldTrigger ? 'var(--red)' : 'var(--green)'}`,
          }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '4px' }}>
              <span style={{ color: e.shouldTrigger ? 'var(--red)' : 'var(--green)', fontSize: '8px' }}>
                {e.shouldTrigger ? '⚠ SHOULD TRIGGER' : '✓ BENIGN'}
              </span>
              <span style={{ color: 'var(--text-dim)', fontSize: '8px' }}>[{e.format}]</span>
            </div>
            <div style={{ color: 'var(--text-dim)', fontSize: '8px', marginBottom: '3px' }}>{e.description}</div>
            <pre style={{
              color: '#86efac', fontSize: '8px', lineHeight: 1.5, margin: 0,
              whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '80px', overflowY: 'auto',
            }}>
              {e.raw.length > 300 ? e.raw.slice(0, 300) + '...' : e.raw}
            </pre>
          </div>
        ))}
      </div>

      {/* Unit test assertions */}
      {assertions.length > 0 && (
        <div style={{ padding: '14px 16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--blue)', marginBottom: '8px' }}>
            ✅ Unit Test Assertions
          </div>
          {assertions.map((a, i) => (
            <div key={i} style={{
              marginBottom: '8px', padding: '8px 12px', background: 'var(--s2)', border: '1px solid var(--border)',
            }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-bright)', marginBottom: '4px' }}>
                Test {i + 1}: {a.expectedRiskLevel}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginBottom: '4px' }}>
                Given: {a.givenDescription}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--green)', lineHeight: 1.6 }}>
                Expect: {Object.entries(a.expectedFields).map(([k, v]) => `${k} ${v}`).join(', ')} · rows: {a.expectedRowCount}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Expected output format */}
      <div style={{ padding: '14px 16px', borderTop: '1px solid var(--border)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--amber)', marginBottom: '8px' }}>
          📋 Expected Notable Event Output
        </div>
        <pre style={{
          fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
          lineHeight: 1.5, whiteSpace: 'pre', overflowX: 'auto',
          background: 'var(--bg)', padding: '12px', border: '1px solid var(--border)',
        }}>
          {expectedOutput}
        </pre>
      </div>

      {/* Format reference */}
      <div style={{ padding: '14px 16px', borderTop: '1px solid var(--border)' }}>
        <button className="log-toggle" onClick={() => setShowExamples(!showExamples)} style={{ marginBottom: showExamples ? '10px' : '0' }}>
          <span className="dot" />{showExamples ? 'Hide' : 'Show'} All Event Format Examples
        </button>
        {showExamples && Object.entries(formatExamples).map(([key, value]) => (
          <div key={key} style={{ marginBottom: '8px' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginBottom: '3px' }}>{key}:</div>
            <pre style={{
              fontFamily: 'var(--mono)', fontSize: '8px', color: '#86efac',
              lineHeight: 1.4, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              background: 'var(--bg)', padding: '6px 10px', border: '1px solid var(--border)',
              maxHeight: '80px', overflowY: 'auto',
            }}>
              {typeof value === 'string' ? value.slice(0, 400) : JSON.stringify(value, null, 2).slice(0, 400)}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}
