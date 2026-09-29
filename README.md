# harness-gate

A fail-closed gate between an AI agent and an action. Zero dependencies, Node 20+, Apache-2.0.

**What it does today (tested: `npm test`, 55 checks):**
- Classifies a tool call into read / draft / write_record / message_out / money / clinical / regulated_filing / unknown by name.
- Default policy: reads and drafts go ahead; a message out, a clinical step or a regulated filing is held for a person; money is denied; anything unknown is held.
- Scans the arguments and only ever makes a verdict stricter: instruction-like text aimed at the agent, credentials, patient-identifier patterns, destructive shell patterns.
- Never trusts the caller's own label. Any error or malformed input is a hold.
- Writes a hash-only, hash-chained local ledger (`~/.harness/ledger.jsonl`). Arguments are never stored. `verify` detects an edited or deleted entry.
- Ships a Claude Code `PreToolUse` hook adapter: `harness-gate hook`.

**What it does NOT do:** it is rules, not a model. It does not judge clinical content, does not replace a physician's signature, and the PHI patterns are a tripwire, not de-identification. There is no local decision model in it yet, and the ledger is local (not yet anchored to hashcare).

## Use it
    echo '{"tool":"send_message","args":{"body":"hi"}}' | node bin/harness-gate.mjs decide   # exit 0 allow, 3 hold, 4 deny
    node bin/harness-gate.mjs verify
    node bin/harness-gate.mjs tail 5

Claude Code hook (`~/.claude/settings.json`):

    { "hooks": { "PreToolUse": [ { "matcher": "mcp__.*|Bash", "hooks": [ { "type": "command", "command": "node /path/to/harness-gate/bin/harness-gate.mjs hook" } ] } ] } }

An allowed call prints nothing, so your normal permission flow is unchanged. A held call becomes an "ask"; a denied one is denied.
