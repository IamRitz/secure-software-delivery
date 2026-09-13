// Tier 0 policy guide coverage. Without these, a new policy key renders with
// no explanation and nothing fails; a stale break-glass sentence tells a
// developer an override exists when the gate would refuse it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  buildReport,
  renderMarkdown,
  POLICY_GUIDE_HEADING
} from '../security/scripts/format-findings.mjs';
import {
  BREAK_GLASS_TEXT,
  POLICY_ADVISORIES
} from '../security/scripts/policy-advisories.mjs';
import {
  markBreakGlassEligibility,
  parseSimplePolicy
} from '../security/scripts/security-gate.mjs';

const policy = parseSimplePolicy(readFileSync('security/policy.yaml', 'utf8'));
const ACTIONS = new Set(['BLOCK', 'BLOCK_DEPLOY', 'EXCEPTION', 'LOG']);

// Every leaf in policy.yaml whose value is a gate action is a policy key.
function policyYamlKeys(node, prefix = '') {
  return Object.entries(node).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object') return policyYamlKeys(value, path);
    return ACTIONS.has(value) ? [path] : [];
  });
}

// Keys the gates emit as literals without a policy.yaml entry (integrity
// failures, the hard-coded layer-secret block). Read from the source so a new
// literal is caught too.
function literalGateKeys() {
  return ['security/scripts/security-gate.mjs', 'security/scripts/image-gate.mjs'].flatMap((file) =>
    [...readFileSync(file, 'utf8').matchAll(/policyRule: '([a-z_]+\.[a-z_]+)'/g)].map((m) => m[1])
  );
}

const EMITTED_KEYS = [...new Set([...policyYamlKeys(policy), ...literalGateKeys()])].sort();

describe('policy guide: coverage', () => {
  it('finds the policy keys it is meant to cover', () => {
    // Guards the extractor itself: an empty list would make the next test vacuous.
    assert.ok(EMITTED_KEYS.includes('dependencies.critical_with_fix'));
    assert.ok(EMITTED_KEYS.includes('gate.report_integrity'));
    assert.ok(EMITTED_KEYS.includes('image.report_integrity'));
    assert.ok(EMITTED_KEYS.includes('image.secret'));
    assert.ok(!EMITTED_KEYS.some((key) => key.startsWith('break_glass.')));
  });

  it('every policy key the gates can emit has advisory text', () => {
    const missing = EMITTED_KEYS.filter((key) => !Object.hasOwn(POLICY_ADVISORIES, key));
    assert.deepEqual(missing, [], `add policy-advisories.mjs entries for: ${missing.join(', ')}`);
  });

  it('no advisory text exists for a key the gates cannot emit (stale entry)', () => {
    const stale = Object.keys(POLICY_ADVISORIES).filter((key) => !EMITTED_KEYS.includes(key));
    assert.deepEqual(stale, []);
  });

  it('every entry is complete', () => {
    for (const [key, entry] of Object.entries(POLICY_ADVISORIES)) {
      assert.ok(entry.meaning?.length > 20, `${key} meaning`);
      assert.ok(entry.why?.length > 20, `${key} why`);
      assert.ok(Object.hasOwn(BREAK_GLASS_TEXT, entry.breakGlass), `${key} breakGlass`);
    }
  });

  it('fixed text never names a version number', () => {
    for (const [key, entry] of Object.entries(POLICY_ADVISORIES)) {
      assert.ok(!/\d+\.\d+/.test(JSON.stringify(entry)), `${key} must not state a version`);
    }
  });
});

describe('policy guide: break-glass statements match the gate', () => {
  function actionFor(key) {
    const value = key.split('.').reduce((node, part) => node?.[part], policy);
    if (ACTIONS.has(value)) return value;
    // Literal keys: image.* integrity/secret block deploys; gate.* blocks.
    return key.startsWith('image.') ? 'BLOCK_DEPLOY' : 'BLOCK';
  }

  for (const key of EMITTED_KEYS) {
    it(key, () => {
      const action = actionFor(key);
      const [finding] = [{ policyRule: key, action }];
      markBreakGlassEligibility(policy, [finding]);
      const stated = POLICY_ADVISORIES[key].breakGlass;

      assert.equal(stated === 'eligible', finding.breakGlassEligible, 'eligible must match the gate');
      if (action === 'LOG' || action === 'EXCEPTION') {
        assert.equal(stated, 'not-needed');
      } else if (action === 'BLOCK_DEPLOY') {
        assert.equal(stated === 'not-offered' || stated === 'never', true);
      } else {
        assert.ok(['eligible', 'never'].includes(stated));
      }
    });
  }
});

describe('policy guide: rendering', () => {
  const gate = {
    verdict: 'BLOCK',
    findings: [
      { source: 'npm-audit', id: 'a', severity: 'critical', action: 'BLOCK', policyRule: 'dependencies.critical_with_fix', reason: 'r' },
      { source: 'osv-scanner', id: 'b', severity: 'critical', action: 'EXCEPTION', policyRule: 'dependencies.critical_no_fix', reason: 'r' },
      { source: 'npm-audit', id: 'c', severity: 'critical', action: 'BLOCK', policyRule: 'dependencies.critical_with_fix', reason: 'r' },
      { source: 'semgrep', id: 'd', severity: 'low', action: 'LOG', policyRule: 'sast.low', reason: 'r' }
    ]
  };
  const markdown = renderMarkdown(buildReport({ gate }));

  it('explains why one Critical blocked while another passed', () => {
    assert.ok(markdown.includes(POLICY_GUIDE_HEADING));
    assert.match(markdown, /`dependencies\.critical_with_fix`/);
    assert.match(markdown, /`dependencies\.critical_no_fix`/);
    assert.match(markdown, /fix availability does/);
  });

  it('renders each key once and omits LOG-only keys', () => {
    assert.equal(markdown.split('**`dependencies.critical_with_fix`**').length - 1, 1);
    assert.ok(!markdown.includes('`sast.low`'));
  });

  it('a clean run renders no guide', () => {
    assert.ok(!renderMarkdown(buildReport({ gate: { verdict: 'PASS', findings: [] } })).includes(POLICY_GUIDE_HEADING));
  });

  it('secrets state the fixed remedy and no override', () => {
    const md = renderMarkdown(
      buildReport({
        gate: { verdict: 'BLOCK', findings: [{ source: 'trufflehog', id: 'AWS', action: 'BLOCK', policyRule: 'secrets.verified', reason: 'r' }] }
      })
    );
    assert.match(md, /Rotate or revoke the credential first/);
    assert.match(md, /never available/);
  });
});
