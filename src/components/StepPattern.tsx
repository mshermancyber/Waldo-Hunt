import type { Pattern } from '../types';

interface StepPatternProps {
  selected: Pattern[];
  onToggle: (p: Pattern) => void;
}

const PATTERNS: { val: Pattern; icon: string; cert: string; name: string; desc: string; indicators: string[] }[] = [
  {
    val: 'sabotage',
    icon: '💥',
    cert: 'CERT Pattern 1',
    name: 'IT Sabotage',
    desc: 'Deliberate destruction or disruption of systems, data, and infrastructure by a trusted insider.',
    indicators: ['Mass Deletion', 'Config Tampering', 'Backup Destruction'],
  },
  {
    val: 'ip_theft',
    icon: '📤',
    cert: 'CERT Pattern 2',
    name: 'IP Theft',
    desc: 'Exfiltration of proprietary data, source code, trade secrets, or customer information.',
    indicators: ['Bulk Downloads', 'Repo Cloning', 'Cross-Account Movement'],
  },
  {
    val: 'fraud',
    icon: '💸',
    cert: 'CERT Pattern 3',
    name: 'Fraud',
    desc: 'Unauthorized financial transactions, resource abuse, or manipulation of billing/payment systems.',
    indicators: ['Priv Escalation', 'Account Creation', 'Policy Bypass'],
  },
  {
    val: 'espionage',
    icon: '🕵️',
    cert: 'CERT Pattern 4',
    name: 'Espionage',
    desc: 'Sustained reconnaissance, credential harvesting, and data access for competitive or nation-state advantage.',
    indicators: ['Recon', 'Cred Harvesting', 'Lateral Movement', 'C2'],
  },
  {
    val: 'data_manip',
    icon: '📊',
    cert: 'CERT Pattern 5',
    name: 'Data Manipulation',
    desc: 'Insider alters, falsifies, or poisons data to cause incorrect business decisions, conceal fraud, or mislead stakeholders.',
    indicators: ['Report Falsification', 'Record Altering', 'Data Poisoning'],
  },
  {
    val: 'third_party',
    icon: '🏢',
    cert: 'CERT Pattern 6',
    name: 'Third-Party / Contractor',
    desc: 'Abuse of vendor, partner, or contractor access to systems — pivoting, data scraping, or supply chain insertion.',
    indicators: ['Vendor Abuse', 'MSP Pivot', 'Supply Chain'],
  },
  {
    val: 'disclosure',
    icon: '📰',
    cert: 'CERT Pattern 7',
    name: 'Unauthorized Disclosure',
    desc: 'Insider leaks sensitive information to media, regulators, competitors, or social platforms without authorization.',
    indicators: ['Media Leak', 'Whistleblowing', 'Data Transfer'],
  },
  {
    val: 'workplace',
    icon: '🛡️',
    cert: 'CERT Pattern 8',
    name: 'Workplace Violence / Harassment',
    desc: 'Threats, stalking, intimidation, or harassment by an insider — with digital evidence across communication and physical security systems.',
    indicators: ['Digital Stalking', 'Threats', 'Surveillance'],
  },
];

export function StepPattern({ selected, onToggle }: StepPatternProps) {
  return (
    <div>
      <div className="sec-head">
        <div className="sec-eyebrow">Step 2 of 5</div>
        <div className="sec-title">Select Attack Patterns</div>
        <div className="sec-desc">
          Choose one or more CERT/CC insider threat patterns. Multi-select enables combined coverage across patterns.
        </div>
      </div>
      <div className="pattern-grid">
        {PATTERNS.map((p) => {
          const isSelected = selected.includes(p.val);
          return (
            <div
              key={p.val}
              className={`p-card ${isSelected ? 'selected' : ''}`}
              onClick={() => onToggle(p.val)}
            >
              <div style={{ position: 'absolute', top: '10px', right: '10px' }}>
                <div
                  className="a-chk"
                  style={{
                    position: 'static',
                    width: '16px',
                    height: '16px',
                    background: isSelected ? 'var(--amber)' : 'var(--bg)',
                    borderColor: isSelected ? 'var(--amber)' : 'var(--border2)',
                  }}
                >
                  {isSelected ? '✓' : ''}
                </div>
              </div>
              <div className="p-icon">{p.icon}</div>
              <div className="p-cert">{p.cert}</div>
              <div className="p-name">{p.name}</div>
              <div className="p-desc">{p.desc}</div>
              <div className="p-indicators">
                {p.indicators.map((ind) => (
                  <span key={ind} className="p-ind">{ind}</span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
