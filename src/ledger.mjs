import { appendFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { homedir } from 'node:os';
import { sha256, canonical } from './decide.mjs';

export const ledgerPath = () => process.env.HARNESS_LEDGER || `${homedir()}/.harness/ledger.jsonl`;

function lastHash(p) {
  if (!existsSync(p)) return '0'.repeat(64);
  const lines = readFileSync(p, 'utf8').trim().split('\n').filter(Boolean);
  return lines.length ? JSON.parse(lines[lines.length - 1]).hash : '0'.repeat(64);
}
// Hash-only: the arguments are never stored, only their hash. Entries chain, so an edit or deletion shows.
export function record(action, result, p = ledgerPath()) {
  mkdirSync(dirname(p), { recursive: true });
  const body = { ts: new Date().toISOString(), tool: action.tool, site: action.site ?? null, class: result.class,
    verdict: result.verdict, reasons: result.reasons, argsHash: result.argsHash, prev: lastHash(p) };
  const entry = { ...body, hash: sha256(canonical(body)) };
  appendFileSync(p, JSON.stringify(entry) + '\n', { mode: 0o600 });
  return entry;
}
export function verify(p = ledgerPath()) {
  if (!existsSync(p)) return { ok: true, entries: 0 };
  let prev = '0'.repeat(64), n = 0;
  for (const line of readFileSync(p, 'utf8').trim().split('\n').filter(Boolean)) {
    const e = JSON.parse(line); const { hash, ...body } = e; n++;
    if (body.prev !== prev || sha256(canonical(body)) !== hash) return { ok: false, brokenAt: n, entries: n };
    prev = hash;
  }
  return { ok: true, entries: n };
}
