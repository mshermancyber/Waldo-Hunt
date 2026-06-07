import { useMemo } from 'react';
import { useWizardState } from './hooks/useWizardState';
import { ACTIVITIES } from './data/activities';
import { ProgressBar } from './components/ProgressBar';
import { StepEnv } from './components/StepEnv';
import { StepPattern } from './components/StepPattern';
import { StepActivity } from './components/StepActivity';
import { StepLogSources } from './components/StepLogSources';
import { StepOutput } from './components/StepOutput';
import type { SavedConfig } from './types';
import './App.css';

export default function App() {
  const w = useWizardState();

  // Combine activities from all selected patterns
  const allActivities = useMemo(() => {
    const seen = new Set<string>();
    const result: { val: string; icon: string; title: string; desc: string }[] = [];
    w.patterns.forEach((p) => {
      (ACTIVITIES[p || ''] || []).forEach((a) => {
        if (!seen.has(a.val)) {
          seen.add(a.val);
          result.push(a);
        }
      });
    });
    return result;
  }, [w.patterns]);

  const canAdvance = (): boolean => {
    switch (w.step) {
      case 0: return w.env !== null;
      case 1: return w.patterns.length > 0;
      case 2: return w.activities.length > 0;
      case 3: return true;
      default: return false;
    }
  };

  const handleLoadConfig = (config: SavedConfig) => {
    w.loadConfig(config);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="wrap">
      <header>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ position: 'relative', flexShrink: 0 }}>
            <div style={{
              width: '48px', height: '48px', background: 'var(--s2)',
              border: '1px solid var(--border)', display: 'flex',
              alignItems: 'center', justifyContent: 'center', fontSize: '24px',
            }}>
              🔍
            </div>
          </div>
          <div>
            <div className="logo">Waldo<span>Hunt</span></div>
            <div className="header-sub">Insider Threat SPL Generator</div>
          </div>
        </div>
        <div className="header-badges">
          <span className={`badge ${w.step >= 0 ? 'active' : ''}`}>CERT/CC Framework</span>
          <span className={`badge ${w.step >= 4 ? 'active' : ''}`}>MITRE ATT&CK</span>
          <span className="badge">Multi-Export</span>
        </div>
      </header>

      <ProgressBar step={w.step} onGo={w.go} />

      {/* Step 0 — Environment */}
      <div className={`section ${w.step === 0 ? 'visible' : ''}`}>
        <StepEnv selected={w.env} onSelect={w.setEnv} />
        <div className="nav">
          <div />
          <button className="btn btn-primary" disabled={!canAdvance()} onClick={() => w.advance(0)}>
            Next: Select Patterns →
          </button>
        </div>
      </div>

      {/* Step 1 — Patterns (multi-select) */}
      <div className={`section ${w.step === 1 ? 'visible' : ''}`}>
        <StepPattern selected={w.patterns} onToggle={w.togglePattern} />
        <div className="nav">
          <button className="btn btn-ghost" onClick={() => w.go(0)}>← Back</button>
          <button className="btn btn-primary" disabled={!canAdvance()} onClick={() => w.advance(1)}>
            Next: Select Activities →
          </button>
        </div>
      </div>

      {/* Step 2 — Activities */}
      <div className={`section ${w.step === 2 ? 'visible' : ''}`}>
        <StepActivity
          patterns={w.patterns}
          activities={allActivities}
          selected={w.activities}
          onToggle={w.toggleActivity}
        />
        <div className="nav">
          <button className="btn btn-ghost" onClick={() => w.go(1)}>← Back</button>
          <button className="btn btn-primary" disabled={!canAdvance()} onClick={() => w.advance(2)}>
            Next: Configure Logs →
          </button>
        </div>
      </div>

      {/* Step 3 — Log Sources */}
      <div className={`section ${w.step === 3 ? 'visible' : ''}`}>
        <StepLogSources
          env={w.env}
          activities={w.activities}
          awsLogs={w.awsLogs}
          onpremLogs={w.onpremLogs}
          overrides={w.overrides}
          onToggleLog={w.toggleLog}
          onOverride={w.updateOverride}
        />
        <div className="nav">
          <button className="btn btn-ghost" onClick={() => w.go(2)}>← Back</button>
          <button className="btn btn-amber" onClick={() => w.advance(3)}>
            Generate Output →
          </button>
        </div>
      </div>

      {/* Step 4 — Output (tabbed) */}
      <div className={`section ${w.step === 4 ? 'visible' : ''}`}>
        <StepOutput
          env={w.env}
          patterns={w.patterns}
          activities={w.activities}
          awsLogs={w.awsLogs}
          onpremLogs={w.onpremLogs}
          overrides={w.overrides}
          onLoad={handleLoadConfig}
        />
        <div className="nav">
          <button className="btn btn-ghost" onClick={() => w.go(3)}>← Back</button>
          <button className="btn btn-ghost" onClick={w.resetAll}>Start Over</button>
        </div>
      </div>
    </div>
  );
}
