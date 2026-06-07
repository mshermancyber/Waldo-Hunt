import { PLAYBOOKS } from '../data/playbooks';
import type { Playbook } from '../data/playbooks';

interface DetectionPlaybookProps {
  activity: string;
}

export function DetectionPlaybook({ activity }: DetectionPlaybookProps) {
  const playbook: Playbook | undefined = PLAYBOOKS[activity];

  if (!playbook) {
    return (
      <div className="log-rec-section" style={{ marginTop: '20px' }}>
        <div className="log-rec-hd">📋 Response Playbook</div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)', padding: '12px' }}>
          No playbook defined for this activity type. Follow standard SOC incident response procedures.
        </div>
      </div>
    );
  }

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">
        📋 Response Playbook — {activity.replace(/_/g, ' ')}
      </div>

      <div style={{ padding: '0 4px' }}>
        {/* SLA + Contact */}
        <div style={{
          display: 'flex', gap: '12px', marginBottom: '14px',
          padding: '10px 12px', background: 'var(--s2)', border: '1px solid var(--border)',
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '2px' }}>SLA</div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '18px', fontWeight: 700, color: 'var(--red)' }}>{playbook.sla}</div>
          </div>
          <div style={{ flex: 2 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '2px' }}>Contact</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-bright)' }}>{playbook.contactRole}</div>
          </div>
        </div>

        {/* Immediate Actions */}
        <PlaybookSection title="🚨 Immediate Actions" items={playbook.immediateActions} color="var(--red)" />

        {/* Investigation Steps */}
        <PlaybookSection title="🔍 Investigation Steps" items={playbook.investigationSteps} color="var(--blue)" />

        {/* Containment */}
        <PlaybookSection title="🛡 Containment Actions" items={playbook.containmentActions} color="var(--amber)" />

        {/* Evidence Preservation */}
        <PlaybookSection title="🔒 Evidence Preservation" items={playbook.evidencePreservation} color="var(--green)" />

        {/* Escalation */}
        <div style={{
          marginTop: '12px', padding: '10px 12px',
          background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
        }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--red)', marginBottom: '4px' }}>
            ⬆ ESCALATION CRITERIA
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', lineHeight: 1.6 }}>
            {playbook.escalationCriteria}
          </div>
        </div>
      </div>
    </div>
  );
}

function PlaybookSection({ title, items, color }: { title: string; items: string[]; color: string }) {
  return (
    <div style={{ marginBottom: '10px' }}>
      <div style={{
        fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.08em',
        color, marginBottom: '6px',
      }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {items.map((item, i) => (
          <div key={i} style={{
            display: 'flex', gap: '8px', alignItems: 'flex-start',
            padding: '4px 8px', borderLeft: `2px solid ${color}33`,
          }}>
            <span style={{
              fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)',
              flexShrink: 0, minWidth: '16px',
            }}>
              {i + 1}.
            </span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', lineHeight: 1.5 }}>
              {item}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
