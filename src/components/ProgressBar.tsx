interface ProgressBarProps {
  step: number;
  onGo: (n: number) => void;
}

const STEPS = ['Environment', 'Attack Pattern', 'Activities', 'Log Sources', 'SPL Output'];

export function ProgressBar({ step, onGo }: ProgressBarProps) {
  return (
    <div className="progress">
      {STEPS.map((label, i) => (
        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: '0' }}>
          <div
            className={`prog-step ${i === step ? 'active' : i < step ? 'done' : ''}`}
            onClick={() => { if (i < step) onGo(i); }}
          >
            <div className="prog-num">{i + 1}</div>
            <div className="prog-label">{label}</div>
          </div>
          {i < STEPS.length - 1 && <div className="prog-sep" />}
        </span>
      ))}
    </div>
  );
}
