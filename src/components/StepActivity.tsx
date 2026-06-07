import type { Pattern, Activity } from '../types';

interface StepActivityProps {
  patterns: Pattern[];
  activities: Activity[];
  selected: string[];
  onToggle: (val: string) => void;
}

export function StepActivity({ patterns, activities, selected, onToggle }: StepActivityProps) {
  const patternLabels: Record<string, string> = {
    sabotage: 'IT Sabotage', ip_theft: 'IP Theft', fraud: 'Fraud', espionage: 'Espionage',
  };

  return (
    <div>
      <div className="sec-head">
        <div className="sec-eyebrow">Step 3 of 5</div>
        <div className="sec-title">Select Activities</div>
        <div className="sec-desc">
          Choose one or more insider threat activities to generate SPL detections for.
          {patterns.length > 1 && (
            <span style={{ color: 'var(--amber)' }}>
              {' '}Showing activities from {patterns.length} patterns: {patterns.map(p => p ? patternLabels[p] : '').join(', ')}
            </span>
          )}
        </div>
      </div>
      <div className="act-grid" id="act-grid">
        {activities.map((a) => (
          <div
            key={a.val}
            className={`a-card ${selected.includes(a.val) ? 'selected' : ''}`}
            onClick={() => onToggle(a.val)}
          >
            <div className="a-chk">{selected.includes(a.val) ? '✓' : ''}</div>
            <div className="a-icon">{a.icon}</div>
            <div className="a-title">{a.title}</div>
            <div className="a-desc">{a.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
