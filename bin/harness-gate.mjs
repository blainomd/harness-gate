#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { decide } from '../src/decide.mjs';
import { record, verify, ledgerPath } from '../src/ledger.mjs';

const [cmd] = process.argv.slice(2);
const stdin = () => { try { return JSON.parse(readFileSync(0, 'utf8')); } catch { return null; } };

if (cmd === 'decide') {
  const a = stdin(); const r = decide(a); record(a || { tool: '?' }, r);
  console.log(JSON.stringify(r, null, 2)); process.exit(r.verdict === 'allow' ? 0 : r.verdict === 'hold' ? 3 : 4);
} else if (cmd === 'hook') {
  // Claude Code PreToolUse adapter. allow = print nothing (normal permission flow stays); hold = ask; deny = deny.
  const ev = stdin(); let out = null;
  try {
    const tool = ev?.tool_name || '';
    const args = tool === 'Bash' ? { command: ev.tool_input?.command } : ev?.tool_input;
    const r = decide(tool === 'Bash' ? { tool: 'shell', args } : { tool, args });
    if (tool === 'Bash' && r.verdict === 'allow' && r.reasons.length === 0) { /* ordinary shell: not logged, not asked */ }
    else {
      record({ tool }, r);
      if (r.verdict !== 'allow') out = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: r.verdict === 'deny' ? 'deny' : 'ask',
        permissionDecisionReason: `harness-gate (${r.class}): ${r.reasons.join('; ') || 'held'}` } };
    }
  } catch (e) {
    out = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: 'harness-gate error: held' } };
  }
  if (out) console.log(JSON.stringify(out));
} else if (cmd === 'verify') {
  const v = verify(); console.log(JSON.stringify({ path: ledgerPath(), ...v })); process.exit(v.ok ? 0 : 1);
} else if (cmd === 'tail') {
  const n = Number(process.argv[3] || 10); try { console.log(readFileSync(ledgerPath(), 'utf8').trim().split('\n').slice(-n).join('\n')); } catch { console.log('(empty)'); }
} else { console.log('usage: harness-gate decide|hook|verify|tail   (decide/hook read JSON on stdin)'); process.exit(2); }
