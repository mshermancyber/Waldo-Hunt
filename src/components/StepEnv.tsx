import type { Environment } from '../types';

interface StepEnvProps {
  selected: Environment;
  onSelect: (env: Environment) => void;
}

const ENVS: { val: Environment; icon: string; name: string; desc: string; tags: string[] }[] = [
  {
    val: 'aws',
    icon: '☁️',
    name: 'AWS Cloud',
    desc: 'Cloud-native detection with CloudTrail, GuardDuty, S3 access logs, VPC Flow Logs, Macie, and more.',
    tags: ['CloudTrail', 'GuardDuty', 'S3', 'VPC', 'Macie', 'IAM'],
  },
  {
    val: 'onprem',
    icon: '🖥️',
    name: 'On-Prem / Hybrid',
    desc: 'Traditional infrastructure with Active Directory, Windows Event Logs, EDR, DLP, and proxy/web gateway.',
    tags: ['AD', 'WinEvent', 'EDR', 'DLP', 'Proxy'],
  },
  {
    val: 'both',
    icon: '🔀',
    name: 'Hybrid',
    desc: 'Combined coverage spanning both AWS cloud and on-prem assets — full detection surface.',
    tags: ['AWS + On-Prem', 'All Sources'],
  },
];

export function StepEnv({ selected, onSelect }: StepEnvProps) {
  return (
    <div>
      <div className="sec-head">
        <div className="sec-eyebrow">Step 1 of 5</div>
        <div className="sec-title">Select Environment</div>
        <div className="sec-desc">
          Choose your target deployment to surface the right log sources and SPL templates.
        </div>
      </div>
      <div className="env-grid">
        {ENVS.map((env) => (
          <div
            key={env.val}
            className={`env-card ${selected === env.val ? 'selected' : ''}`}
            onClick={() => onSelect(env.val)}
          >
            <div className="env-icon">{env.icon}</div>
            <div className="env-name">{env.name}</div>
            <div className="env-desc">{env.desc}</div>
            <div className="env-sources">
              {env.tags.map((t) => (
                <span key={t} className="env-tag">{t}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
