import { createHash } from 'node:crypto';
import { classify, POLICY } from './manifest.mjs';
import { scan } from './scan.mjs';

export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// decide({tool, args, site?, actor?}) -> {verdict: allow|hold|deny, class, reasons[], argsHash}
// Fail closed: anything malformed or thrown is a hold. Nothing here can turn a hold into an allow.
export function decide(action) {
  try {
    if (!action || typeof action !== 'object' || !action.tool) return closed('malformed action: no tool name');
    const cls = classify(action.tool); // never taken from the caller: an agent must not be able to relabel its own action
    const s = scan(action.args);
    const reasons = [];
    let verdict = POLICY[cls];
    if (cls === 'unknown') reasons.push('tool not in the manifest: held until a person classifies it');
    if (cls === 'message_out') reasons.push('a message leaves the device: a person sends it');
    if (cls === 'money') reasons.push('money never moves automatically');
    if (cls === 'clinical') reasons.push('clinical: a licensed physician decides, not an agent');
    if (cls === 'regulated_filing') reasons.push('regulated filing: a person signs and submits');
    const outward = ['message_out', 'money', 'regulated_filing', 'clinical'].includes(cls);
    if (s.secret) { verdict = outward ? 'deny' : stricter(verdict, 'hold'); reasons.push('a credential or key appears in the arguments'); }
    if (s.injection) { verdict = stricter(verdict, outward ? 'deny' : 'hold'); reasons.push('instruction-like text aimed at the agent in the arguments'); }
    if (s.phi.length) { verdict = stricter(verdict, cls === 'read' ? 'hold' : outward ? 'deny' : 'hold'); reasons.push('possible patient identifiers: ' + s.phi.join(', ')); }
    if (s.destructive) { verdict = stricter(verdict, 'hold'); reasons.push('destructive or irreversible command pattern'); }
    return { verdict, class: cls, reasons, argsHash: sha256(canonical(action.args ?? null)) };
  } catch (e) {
    return closed('gate error: ' + (e && e.message ? e.message.slice(0, 80) : 'unknown'));
  }
}
const RANK = { allow: 0, hold: 1, deny: 2 };
const stricter = (a, b) => (RANK[b] > RANK[a] ? b : a);
const closed = (why) => ({ verdict: 'hold', class: 'unknown', reasons: [why], argsHash: null });
