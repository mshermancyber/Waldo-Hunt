import { useState } from 'react';
import { generateServiceNow, generateJira, generateSOARCase, formatServiceNowJSON, formatJiraJSON, formatSOARJSON } from '../data/incidentTemplates';
import { ACTIVITIES } from '../data/activities';
import type { Pattern } from '../types';

interface IncidentTemplatesProps {
  activity: string;
  env: 'aws' | 'onprem' | 'both';
  patterns: Pattern[];
}

type ITSMPlatform = 'servicenow' | 'jira' | 'soar';

export function IncidentTemplates({ activity, env, patterns }: IncidentTemplatesProps) {
  const [platform, setPlatform] = useState<ITSMPlatform>('servicenow');
  const [copied, setCopied] = useState(false);

  const actLabels: Record<string, string> = {};
  patterns.forEach(p => (ACTIVITIES[p || ''] || []).forEach(a => { actLabels[a.val] = a.title; }));

  const title = actLabels[activity] || activity.replace(/_/g, ' ');
  const user = env === 'aws' ? 'arn:aws:iam::123456789012:user/insider_threat' : 'CORP\\jsmith';
  const risk = 'HIGH';

  const generateContent = (): string => {
    const envType = env === 'both' ? 'aws' : env;
    switch (platform) {
      case 'servicenow':
        return formatServiceNowJSON(generateServiceNow(activity, title, envType, user, risk));
      case 'jira':
        return formatJiraJSON(generateJira(activity, title, envType, user, risk));
      case 'soar':
        return formatSOARJSON(generateSOARCase(activity, title, envType, user, risk));
    }
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(generateContent());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const platforms: { val: ITSMPlatform; label: string; icon: string; ext: string }[] = [
    { val: 'servicenow', label: 'ServiceNow', icon: '🔴', ext: 'json' },
    { val: 'jira', label: 'Jira', icon: '🔵', ext: 'json' },
    { val: 'soar', label: 'SOAR (TheHive)', icon: '🟢', ext: 'json' },
  ];

  const content = generateContent();

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">🎫 Incident Ticket Templates</div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px' }}>
        {platforms.map(p => (
          <button key={p.val}
            className={`log-toggle ${platform === p.val ? 'selected' : ''}`}
            onClick={() => { setPlatform(p.val); setCopied(false); }}>
            <span className="dot" />{p.icon} {p.label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <button className="copy-btn" onClick={handleCopy}>{copied ? 'Copied!' : 'Copy JSON'}</button>
      </div>

      {platform === 'servicenow' && (
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
          <TicketField label="Category" value="Security Incident" />
          <TicketField label="Assignment" value="SOC Tier 2" />
          <TicketField label="Urgency" value="2 - High" />
          <TicketField label="Impact" value="2 - Medium" />
        </div>
      )}

      {platform === 'jira' && (
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
          <TicketField label="Project" value="SEC" />
          <TicketField label="Type" value="Incident" />
          <TicketField label="Priority" value="High" />
          <TicketField label="Labels" value="insider-threat, waldohunt" />
        </div>
      )}

      {platform === 'soar' && (
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
          <TicketField label="Severity" value="3" />
          <TicketField label="TLP" value="AMBER" />
          <TicketField label="PAP" value="RED" />
          <TicketField label="Tasks" value="7 auto-generated" />
        </div>
      )}

      <pre style={{
        fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
        background: 'var(--bg)', padding: '12px', border: '1px solid var(--border)',
        lineHeight: 1.5, whiteSpace: 'pre-wrap', maxHeight: '500px', overflowY: 'auto',
      }}>
        {content}
      </pre>
    </div>
  );
}

function TicketField({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ padding: '6px 10px', background: 'var(--bg)', border: '1px solid var(--border)' }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--green)', fontWeight: 600 }}>{value}</div>
    </div>
  );
}
