import { useState } from 'react';

interface SuppressionBuilderProps {
  activity: string;
  env: 'aws' | 'onprem';
}

interface SuppressionRule {
  field: string;
  operator: string;
  value: string;
}

const COMMON_FIELDS: Record<string, string[]> = {
  aws: ['userIdentity.arn', 'sourceIPAddress', 'awsRegion', 'eventName', 'eventSource', 'userAgent', 'requestParameters.bucketName'],
  onprem: ['SubjectUserName', 'SubjectDomainName', 'ComputerName', 'IpAddress', 'WorkstationName', 'EventCode'],
};

export function SuppressionBuilder({ activity, env }: SuppressionBuilderProps) {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [windowMins, setWindowMins] = useState(60);

  const addRule = () => {
    const fields = env === 'aws' ? COMMON_FIELDS.aws : COMMON_FIELDS.onprem;
    setRules([...rules, { field: fields[0], operator: '=', value: '' }]);
  };

  const updateRule = (index: number, updates: Partial<SuppressionRule>) => {
    setRules(rules.map((r, i) => i === index ? { ...r, ...updates } : r));
  };

  const removeRule = (index: number) => {
    setRules(rules.filter((_, i) => i !== index));
  };

  const generateSuppressionStanza = (): string => {
    if (rules.length === 0) return '# No suppression rules defined\n';
    const fields = rules.map(r => `"${r.field}"`).join(', ');
    return `# Splunk ES correlation search suppression
# Activity: ${activity} | Environment: ${env}

[alert.suppress]
alert_suppress = 1
suppress_fields = ${fields}
suppress_period = ${windowMins}m

${rules.map((r, i) => `# Rule ${i + 1}: ${r.field} ${r.operator} "${r.value}"`).join('\n')}
`;
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(generateSuppressionStanza());
  };

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">🚫 Suppression Rule Builder</div>

      <div style={{ padding: '4px 0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>Window:</span>
            <input type="range" min={5} max={360} step={5} value={windowMins}
              onChange={(e) => setWindowMins(parseInt(e.target.value))}
              style={{ accentColor: 'var(--green)', width: '120px' }} />
            <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--green)', fontWeight: 600 }}>{windowMins}m</span>
          </div>
          <button className="copy-btn" onClick={addRule}>+ Add Rule</button>
          {rules.length > 0 && <button className="copy-btn" onClick={handleCopy}>Copy Config</button>}
        </div>

        {rules.map((rule, i) => (
          <div key={i} style={{
            display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '8px',
            padding: '8px 10px', background: 'var(--bg)', border: '1px solid var(--border)',
          }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>IF</span>
            <select className="override-input" value={rule.field}
              onChange={(e) => updateRule(i, { field: e.target.value })}
              style={{ width: 'auto', fontSize: '9px', padding: '4px 8px' }}>
              {(env === 'aws' ? COMMON_FIELDS.aws : COMMON_FIELDS.onprem).map(f => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
            <select className="override-input" value={rule.operator}
              onChange={(e) => updateRule(i, { operator: e.target.value })}
              style={{ width: '80px', fontSize: '9px', padding: '4px 8px' }}>
              <option value="=">=</option>
              <option value="!=">!=</option>
              <option value="IN">IN</option>
              <option value="NOT IN">NOT IN</option>
            </select>
            <input className="override-input" type="text"
              placeholder="value or comma-separated list"
              value={rule.value}
              onChange={(e) => updateRule(i, { value: e.target.value })}
              style={{ flex: 1, fontSize: '9px', padding: '4px 8px' }} />
            <button className="copy-btn" onClick={() => removeRule(i)}
              style={{ borderColor: 'var(--red)', padding: '2px 8px', fontSize: '12px' }}>✕</button>
          </div>
        ))}

        {rules.length === 0 && (
          <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)', padding: '12px' }}>
            Add rules to suppress alerts. Example: suppress if userIdentity.arn IN ('arn:aws:iam::*:role/ci-cd-*', 'arn:aws:iam::*:role/automation-*')
          </div>
        )}

        {rules.length > 0 && (
          <pre style={{
            fontFamily: 'var(--mono)', fontSize: '9px', color: '#86efac',
            background: 'var(--bg)', padding: '12px', marginTop: '10px',
            border: '1px solid var(--border)', lineHeight: 1.6, whiteSpace: 'pre-wrap',
          }}>
            {generateSuppressionStanza()}
          </pre>
        )}
      </div>
    </div>
  );
}
