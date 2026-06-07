import { useMemo } from 'react';
import { getRelevantBundles, getBundleCoveragePercent, CAMPAIGN_BUNDLES } from '../data/campaignBundles';
import type { CampaignBundle } from '../data/campaignBundles';

interface CampaignBundlesProps {
  selectedPatterns: string[];
  selectedActivities: string[];
  onApplyBundle: (bundle: CampaignBundle) => void;
}

export function CampaignBundles({ selectedPatterns, selectedActivities, onApplyBundle }: CampaignBundlesProps) {
  const relevantBundles = useMemo(
    () => getRelevantBundles(selectedPatterns, selectedActivities),
    [selectedPatterns, selectedActivities]
  );

  const allBundles = CAMPAIGN_BUNDLES;

  return (
    <div className="log-rec-section" style={{ marginTop: '20px' }}>
      <div className="log-rec-hd">📦 Campaign-Based Detection Bundles</div>
      <div style={{ padding: '8px 4px' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', lineHeight: 1.6, padding: '8px 12px', marginBottom: '12px' }}>
          Curated detection bundles based on real-world insider threat campaigns. Apply a bundle to auto-select the recommended patterns and activities.
        </div>

        {allBundles.map((bundle) => {
          const relevant = relevantBundles.some(b => b.id === bundle.id);
          const coverage = getBundleCoveragePercent(bundle, selectedActivities);
          return (
            <div key={bundle.id} style={{
              marginBottom: '12px', border: `1px solid ${relevant ? 'var(--amber-dim)' : 'var(--border)'}`,
              background: relevant ? 'rgba(245,158,11,0.04)' : 'var(--s1)',
            }}>
              {/* Header */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '10px 14px', background: 'var(--s2)', borderBottom: '1px solid var(--border)',
                flexWrap: 'wrap', gap: '8px',
              }}>
                <div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-bright)', fontWeight: 600 }}>
                    {bundle.name}
                  </div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '2px' }}>
                    Based on: {bundle.basedOn}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                  {selectedActivities.length > 0 && (
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 8px',
                      background: coverage >= 80 ? 'rgba(34,197,94,0.12)' : coverage >= 40 ? 'rgba(245,158,11,0.12)' : 'transparent',
                      color: coverage >= 80 ? 'var(--green)' : 'var(--text-dim)',
                      border: `1px solid ${coverage >= 80 ? 'var(--green-dim)' : 'var(--border2)'}`,
                    }}>
                      {coverage}% covered
                    </span>
                  )}
                  <button
                    className="copy-btn"
                    style={{ borderColor: 'var(--amber)', color: 'var(--amber)' }}
                    onClick={() => onApplyBundle(bundle)}
                  >
                    Apply Bundle
                  </button>
                </div>
              </div>

              {/* Body */}
              <div style={{ padding: '12px 14px' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text)', lineHeight: 1.7, marginBottom: '12px' }}>
                  {bundle.narrative}
                </div>

                {/* Timeline */}
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--blue)', marginBottom: '6px' }}>
                    ATTACK TIMELINE
                  </div>
                  {bundle.timeline.map((t, i) => (
                    <div key={i} style={{
                      fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)',
                      paddingLeft: '16px', borderLeft: '2px solid var(--blue-dim)', marginLeft: '4px',
                      paddingBottom: i < bundle.timeline.length - 1 ? '8px' : '0', lineHeight: 1.6,
                    }}>
                      {t}
                    </div>
                  ))}
                </div>

                {/* Indicators */}
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--green)', marginBottom: '6px' }}>
                    KEY INDICATORS
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {bundle.indicators.map((ind, i) => (
                      <span key={i} style={{
                        fontFamily: 'var(--mono)', fontSize: '8px', padding: '2px 8px',
                        border: '1px solid var(--green-dim)', color: 'var(--green)',
                        letterSpacing: '0.04em',
                      }}>
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Recommended */}
                <div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', letterSpacing: '0.1em', color: 'var(--amber)', marginBottom: '6px' }}>
                    RECOMMENDED DETECTIONS
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {bundle.recommendedActivities.map((a) => (
                      <span key={a} className="mitre-act-tag" style={{
                        background: selectedActivities.includes(a) ? 'rgba(34,197,94,0.12)' : 'transparent',
                        borderColor: selectedActivities.includes(a) ? 'var(--green-dim)' : 'var(--border2)',
                        color: selectedActivities.includes(a) ? 'var(--green)' : 'var(--text-dim)',
                      }}>
                        {selectedActivities.includes(a) ? '✓ ' : ''}{a.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
