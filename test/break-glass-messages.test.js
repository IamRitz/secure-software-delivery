import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { buildApprovalMessage } from '../server/break-glass/messages.mjs';

const REPO = 'IamRitz/secure-software-delivery';
const SHA = 'abcdef0123456789abcdef0123456789abcdef01';

function baseRequest(findings) {
  return {
    requestId: '11111111-1111-4111-8111-111111111111',
    expiresAt: '2026-01-01T00:00:00.000Z',
    context: { repository: REPO, pullRequest: '12', commitSha: SHA },
    findings
  };
}

function block(msg, type) {
  return msg.blocks.find((b) => b.type === type);
}

describe('buildApprovalMessage layout', () => {
  it('renders header, plain-language summary, technical context, and linked fields', () => {
    const msg = buildApprovalMessage(
      baseRequest([
        { source: 'semgrep', id: 'demo.rule', policyRule: 'sast.high_new', reason: 'high finding is new', location: 'src/app.js:42' }
      ]),
      'C1'
    );
    assert.equal(block(msg, 'header').text.text, 'Break-glass security exception requested');
    // plain-language summary first
    assert.match(block(msg, 'section').text.text, /New high-severity code security issue/);
    // exact technical line kept in the (secondary) context block
    assert.match(block(msg, 'context').elements[0].text, /sast\.high_new: demo\.rule/);

    const fields = msg.blocks.filter((b) => b.type === 'section').find((b) => b.fields).fields;
    const pr = fields.find((f) => f.text.startsWith('*Pull request*'));
    const commit = fields.find((f) => f.text.startsWith('*Commit*'));
    assert.match(pr.text, new RegExp(`<https://github.com/${REPO}/pull/12\\|#12>`));
    assert.match(commit.text, new RegExp(`<https://github.com/${REPO}/commit/${SHA}\\|abcdef012345>`));
  });

  it('adds a real "View finding" blob link for SAST when location is present', () => {
    const msg = buildApprovalMessage(
      baseRequest([{ source: 'semgrep', id: 'demo.rule', policyRule: 'sast.high_new', reason: 'r', location: 'src/app.js:42' }]),
      'C1'
    );
    assert.match(
      block(msg, 'context').elements[0].text,
      new RegExp(`<https://github.com/${REPO}/blob/${SHA}/src/app.js#L42\\|View finding>`)
    );
  });

  it('omits the finding link when location is missing (no faked link)', () => {
    const msg = buildApprovalMessage(
      baseRequest([{ source: 'semgrep', id: 'demo.rule', policyRule: 'sast.high_new', reason: 'r' }]),
      'C1'
    );
    assert.doesNotMatch(block(msg, 'context').elements[0].text, /View finding/);
    assert.doesNotMatch(block(msg, 'context').elements[0].text, /\/blob\//);
  });

  it('maps dependency findings to plain language and adds no blob link', () => {
    const msg = buildApprovalMessage(
      baseRequest([{ source: 'npm-audit', id: 'minimist', policyRule: 'dependencies.critical_with_fix', reason: 'critical; fix available' }]),
      'C1'
    );
    assert.match(block(msg, 'section').text.text, /Critical vulnerable dependency \(fix available\)/);
    assert.doesNotMatch(block(msg, 'context').elements[0].text, /View finding/);
    assert.match(block(msg, 'context').elements[0].text, /dependencies\.critical_with_fix: minimist/);
  });

  it('renders Expires as a local-time Slack date token and suppresses link unfurls', () => {
    const msg = buildApprovalMessage(
      baseRequest([{ source: 'semgrep', id: 'demo.rule', policyRule: 'sast.high_new', reason: 'r' }]),
      'C1'
    );
    assert.equal(msg.unfurl_links, false);
    assert.equal(msg.unfurl_media, false);
    const fields = msg.blocks.filter((b) => b.type === 'section').find((b) => b.fields).fields;
    const expires = fields.find((f) => f.text.startsWith('*Expires*'));
    assert.match(expires.text, /<!date\^\d+\^\{date_short_pretty\} \{time\}\|2026-01-01T00:00:00\.000Z>/);
  });

  it('keeps the Approve/Deny action buttons unchanged', () => {
    const msg = buildApprovalMessage(
      baseRequest([{ source: 'semgrep', id: 'demo.rule', policyRule: 'sast.high_new', reason: 'r' }]),
      'C1'
    );
    const actions = block(msg, 'actions');
    assert.equal(actions.elements.map((e) => e.text.text).join(','), 'Approve,Deny');
    assert.equal(actions.elements[0].action_id, 'breakglass:11111111-1111-4111-8111-111111111111:approve');
  });
});
