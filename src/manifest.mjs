// Action classes and how a tool name maps to one. First match wins; unknown = "unknown" (held).
export const CLASSES = ['read', 'draft', 'write_record', 'message_out', 'money', 'clinical', 'regulated_filing', 'unknown'];

// Default policy per class. allow = proceeds, hold = a human decides, deny = never automatic.
export const POLICY = {
  read: 'allow', draft: 'allow', write_record: 'allow',
  message_out: 'hold', money: 'deny', clinical: 'hold', regulated_filing: 'hold', unknown: 'hold',
};

// Order matters: drafts and leading read verbs first (so "get_lmn_queue" and "send_message_draft" are not
// mistaken for a sign-off or a send), then the risky classes, then the generic verbs.
export const TOOL_RULES = [
  ['write_record', /^shell$/i], // the hook's stand-in for an ordinary shell command; dangerous patterns are scanned separately
  ['write_record', /^browser_|^computer$|^(left_|right_|double_)?click$|^tabs_/i], // page interaction; risky clicks are for the permission system
  ['message_out', /(pull_request|push_files|create_or_update_file|create_issue|add_issue_comment|update_issue|create_pull_request_review|fork_repository|create_repository)/i], // publishes outside the device
  ['draft', /(^|[_.\-])(draft|create_draft|update_draft|compose|preview)([_.\-]|$)/i],
  ['read', /^(get|list|read|search|query|fetch|find|describe|lookup|check|count|view|show|identify|calculate|score|validate|suggest|render|resolve|explain)([_.\-]|$)/i],
  ['money', /(^|[_.\-])(buy|sell|transfer|pay|payment|checkout|charge|refund|invoice|purchase|withdraw|deposit)([_.\-]|$)/i],
  ['clinical', /(approve|sign|attest|swipe_review|generate_lmn|lmn|prescrib|diagnos|order_(lab|med))/i],
  ['regulated_filing', /(prior_auth|submit_claim|file_|submit_|regulatory)/i],
  ['message_out', /(send|reply|forward|post|publish|broadcast|schedule_message|imessage|sms|tweet|offer_care|accept_offer|submit_offer)/i],
  ['write_record', /(^|[_.\-])(create|update|delete|trash|remove|log|set|save|write|edit|move|label|add|put|patch|upsert|merge|start|complete|join|leave|link|register|upload|apply)([_.\-]|$)/i],
  ['read', /(^|[_.\-])(get|list|read|search|query|fetch|find|describe|show|lookup|check|count|export|view)([_.\-]|$)/i],
];

export function classify(tool) {
  const full = String(tool || '');
  const t = full.includes('__') ? full.split('__').pop() : full; // mcp__server__tool -> tool
  for (const [cls, re] of TOOL_RULES) if (re.test(t)) return cls;
  return 'unknown';
}
