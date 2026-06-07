import { useState } from 'react';

interface PeerReviewProps {
  activity: string;
}

interface ReviewItem {
  id: string;
  phase: string;
  question: string;
  guidance: string;
}

const REVIEW_CHECKLIST: ReviewItem[] = [
  // Detection Logic
  { id: 'pr-1', phase: 'Detection Logic', question: 'Does the SPL correctly implement the intended detection?', guidance: 'Verify eventNames, field names, and stat logic match the detection objective. Run against test data and confirm expected output.' },
  { id: 'pr-2', phase: 'Detection Logic', question: 'Are all log sources properly configured and available?', guidance: 'Confirm indexes exist in Splunk, sourcetypes match CIM, and data is being ingested for the required lookback window.' },
  { id: 'pr-3', phase: 'Detection Logic', question: 'Are thresholds appropriate for the environment?', guidance: 'Validate against baseline data. A threshold of 100 might be too sensitive for a large org or miss activity in a small one.' },

  // Performance
  { id: 'pr-4', phase: 'Performance', question: 'Will this search complete within the time window?', guidance: 'Check for expensive commands (join, transaction, subsearch). Verify index bounds. Use tstats or datamodel acceleration where possible.' },
  { id: 'pr-5', phase: 'Performance', question: 'Is the cron schedule appropriate for the detection urgency?', guidance: 'Privilege escalation: every 15 min. Recon: every 6 hours. Match cron to MTTD requirements.' },
  { id: 'pr-6', phase: 'Performance', question: 'Are data model accelerations configured for the referenced datasets?', guidance: 'Verify Authentication, Change_Analysis, Network_Traffic acceleration is enabled for the required period.' },

  // False Positives
  { id: 'pr-7', phase: 'False Positives', question: 'Have known false positive scenarios been identified and excluded?', guidance: 'Document expected FPs (CI/CD pipelines, admin maintenance, security tools). Add exclusions for known-good activity.' },
  { id: 'pr-8', phase: 'False Positives', question: 'Are exclusions specific enough to not create detection gaps?', guidance: 'Excluding by IP can be bypassed. Prefer IAM role ARN exclusions with condition checks. Avoid overly broad exclusions.' },
  { id: 'pr-9', phase: 'False Positives', question: 'Has the detection been run in report mode for the recommended baseline period?', guidance: '14-30 days of silent running. Classify every detection as TP/FP. Only promote when FP rate is acceptable.' },

  // Alerting
  { id: 'pr-10', phase: 'Alerting', question: 'Is the notable event severity appropriate?', guidance: 'Privilege escalation = critical. Recon = medium. Match severity to organizational risk tolerance and incident response SLA.' },
  { id: 'pr-11', phase: 'Alerting', question: 'Are alert suppression rules configured to prevent flooding?', guidance: 'Suppress on user + eventName for 1 hour minimum. Avoid suppressing on fields that could allow an attacker to bypass.' },
  { id: 'pr-12', phase: 'Alerting', question: 'Does the notable event description contain actionable information?', guidance: 'Include: user ARN, count, risk score, affected resources, first/last time, and drilldown search link.' },

  // Operations
  { id: 'pr-13', phase: 'Operations', question: 'Is there a documented response playbook?', guidance: 'SOC must know: who to contact, what to contain, how to preserve evidence, and when to escalate.' },
  { id: 'pr-14', phase: 'Operations', question: 'Has the detection been tested in a tabletop or live-fire exercise?', guidance: 'Run the synthetic event generator output through Splunk. Verify the alert fires and the SOC receives the notable event.' },
  { id: 'pr-15', phase: 'Operations', question: 'Is there a rollback plan if the detection causes operational issues?', guidance: 'Document how to disable the correlation search, adjust thresholds, or roll back to a previous version.' },

  // Compliance
  { id: 'pr-16', phase: 'Compliance', question: 'Are NIST/CIS control mappings documented?', guidance: 'Map to NIST 800-53 and CIS v8 for audit readiness. Attach to detection documentation.' },
  { id: 'pr-17', phase: 'Compliance', question: 'Is the detection review process documented and repeatable?', guidance: 'Include reviewer name, date, findings, and sign-off in the detection repository.' },
];

export function PeerReview({ activity }: PeerReviewProps) {
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [reviewerName, setReviewerName] = useState('');
  const [reviewNotes, setReviewNotes] = useState('');

  const phases = ['Detection Logic', 'Performance', 'False Positives', 'Alerting', 'Operations', 'Compliance'];
  const totalChecked = Object.values(checked).filter(Boolean).length;
  const passPercent = Math.round((totalChecked / REVIEW_CHECKLIST.length) * 100);

  const handleCopyReport = async () => {
    const report = `# Peer Review Report: ${activity.replace(/_/g, ' ')}
Date: ${new Date().toISOString()}
Reviewer: ${reviewerName || '(unsigned)'}
Status: ${passPercent}% complete (${totalChecked}/${REVIEW_CHECKLIST.length} items)

${phases.map(phase => {
  const items = REVIEW_CHECKLIST.filter(i => i.phase === phase);
  return `## ${phase}
${items.map(i => `- [${checked[i.id] ? 'x' : ' '}] ${i.question}`).join('\n')}`;
}).join('\n\n')}

## Review Notes
${reviewNotes || '(none)'}

## Sign-off
Reviewer: ${reviewerName || '_______________'}
Date: ${new Date().toLocaleDateString()}
`;
    await navigator.clipboard.writeText(report);
  };

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">
        🔍 Peer Review Checklist — {activity.replace(/_/g, ' ')}
        <span style={{ color: 'var(--text-dim)', marginLeft: '8px' }}>
          ({totalChecked}/{REVIEW_CHECKLIST.length} — {passPercent}%)
        </span>
      </div>

      {/* Reviewer info */}
      <div style={{ padding: '10px 16px', display: 'flex', gap: '12px', flexWrap: 'wrap', borderBottom: '1px solid var(--border)' }}>
        <input className="override-input" type="text" placeholder="Reviewer name"
          value={reviewerName} onChange={(e) => setReviewerName(e.target.value)}
          style={{ flex: 1, minWidth: '180px', fontSize: '9px' }} />
        <button className="copy-btn" onClick={handleCopyReport}>Copy Report</button>
      </div>

      {/* Checklist */}
      <div style={{ padding: '8px 4px' }}>
        {phases.map(phase => (
          <div key={phase} style={{ marginBottom: '10px' }}>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '9px', letterSpacing: '0.1em',
              color: 'var(--blue)', marginBottom: '6px', paddingLeft: '8px',
            }}>
              ▸ {phase}
            </div>
            {REVIEW_CHECKLIST.filter(i => i.phase === phase).map(item => (
              <div key={item.id} className="log-row" style={{ padding: '6px 14px', cursor: 'pointer' }}
                onClick={() => setChecked(c => ({ ...c, [item.id]: !c[item.id] }))}>
                <div style={{
                  width: '16px', height: '16px', flexShrink: 0, marginTop: '1px',
                  border: `1px solid ${checked[item.id] ? 'var(--green)' : 'var(--border2)'}`,
                  background: checked[item.id] ? 'var(--green)' : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '10px', color: '#000', transition: 'all 0.15s',
                }}>
                  {checked[item.id] ? '✓' : ''}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: '9px',
                    color: checked[item.id] ? 'var(--text-mid)' : 'var(--text-bright)',
                    textDecoration: checked[item.id] ? 'line-through' : 'none',
                  }}>
                    {item.question}
                  </div>
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)',
                    marginTop: '3px', lineHeight: 1.4,
                  }}>
                    {item.guidance}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Review notes */}
      <div style={{ padding: '10px 16px', borderTop: '1px solid var(--border)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '6px' }}>
          REVIEW NOTES
        </div>
        <textarea className="override-input" placeholder="Enter review findings, concerns, or approval notes..."
          value={reviewNotes} onChange={(e) => setReviewNotes(e.target.value)}
          style={{ width: '100%', minHeight: '80px', resize: 'vertical', fontSize: '9px' }} />
      </div>
    </div>
  );
}
