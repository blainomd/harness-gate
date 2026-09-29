// Deterministic scans over an action's arguments. Everything here can only make a verdict stricter.
const INJECTION = [
  /ignore (all |any |your |the )?(previous|prior|above|earlier|safety)? ?(instructions|rules|guidelines|policies)/i,
  /disregard (all |any |your |the )?(previous|prior|above|earlier)? ?(instructions|rules|guidelines)/i,
  /(reveal|print|show|output|repeat) (your |the )?(system prompt|hidden instructions)/i,
  /you are now (in )?(developer|admin|dan|jailbreak|root) mode/i,
  /(run|execute) (this|the following) (payload|command|script)/i,
  /(cat|echo|print|dump|send|upload|curl)[^\n]{0,60}(\.env|id_rsa|credentials|api[_-]?key|service[_-]?role|manifest)/i,
  /(approval|permission|authori[sz]ation)\s+(has\s+|was\s+|is\s+)?(already\s+)?(been\s+)?(granted|given|pre-?approved)/i,
];
const SECRETS = [
  /\bsk-[A-Za-z0-9_-]{16,}/, /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/, /\bghp_[A-Za-z0-9]{30,}/, /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
];
const PHI = [
  ['ssn', /\b\d{3}-\d{2}-\d{4}\b/],
  ['dob', /\b(dob|date of birth|born)\b[^\n]{0,20}\b(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/i],
  ['mrn', /\b(mrn|medical record (number|no)|patient id)\b[^\n]{0,8}\b[A-Z0-9-]{5,}\b/i],
  ['npi_or_dea', /\b(dea)\b[^\n]{0,6}\b[A-Z]{2}\d{7}\b/i],
];
const DESTRUCTIVE = [
  /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(\/|~|\$HOME)(\s|$)/, /\bgit\s+push\b[^\n]*(--force|-f\b)/, /\bdrop\s+(table|database)\b/i,
  /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/, /\bmkfs\b|\bdd\s+if=.*of=\/dev\//, /\bchmod\s+-R\s+777\s+\//,
];

export function flatten(v, out = []) {
  if (v == null) return out;
  if (typeof v === 'string') out.push(v);
  else if (typeof v === 'object') for (const x of Object.values(v)) flatten(x, out);
  else out.push(String(v));
  return out;
}
export function scan(args) {
  const text = flatten(args).join('\n');
  return {
    injection: INJECTION.some((r) => r.test(text)),
    secret: SECRETS.some((r) => r.test(text)),
    phi: PHI.filter(([, r]) => r.test(text)).map(([n]) => n),
    destructive: DESTRUCTIVE.some((r) => r.test(text)),
  };
}
