// The 21 fields of an alert, exactly as the backend's intake accepts them (src/week5/intake.py). These rules give fast feedback in the form;
// the server validates again and is the authority, and its field-level errors are shown against the same inputs.

export type FieldKind = 'alert_id' | 'flow_id' | 'timestamp' | 'ip' | 'port' | 'protocol' | 'score' | 'number';
export type FieldGroup = 'identity' | 'network' | 'detector' | 'features';

export interface FieldDef {
  name: string;
  label: string;
  kind: FieldKind;
  group: FieldGroup;
  hint: string;
  placeholder?: string;
}

export const ALERT_FIELDS: readonly FieldDef[] = [
  { name: 'alert_id', label: 'Alert ID', kind: 'alert_id', group: 'identity', hint: 'Up to 64 characters: letters, digits, . _ : -; must start with a letter or digit.' },
  { name: 'timestamp', label: 'Timestamp', kind: 'timestamp', group: 'identity', hint: 'YYYY-MM-DD HH:MM:SS, no time zone.', placeholder: 'YYYY-MM-DD HH:MM:SS' },
  { name: 'flow_id', label: 'Flow ID', kind: 'flow_id', group: 'identity', hint: 'Up to 128 characters: letters, digits, . _ : -' },
  { name: 'src_ip', label: 'Source IP', kind: 'ip', group: 'network', hint: 'IPv4 or IPv6.' },
  { name: 'src_port', label: 'Source port', kind: 'port', group: 'network', hint: 'Whole number, 0 to 65535.' },
  { name: 'dst_ip', label: 'Destination IP', kind: 'ip', group: 'network', hint: 'IPv4 or IPv6.' },
  { name: 'dst_port', label: 'Destination port', kind: 'port', group: 'network', hint: 'Whole number, 0 to 65535.' },
  { name: 'protocol', label: 'Protocol number', kind: 'protocol', group: 'network', hint: 'IP protocol number, 0 to 255 (6 = TCP, 17 = UDP).' },
  { name: 'detector_score', label: 'Detector score', kind: 'score', group: 'detector', hint: 'The detector’s attack score, from 0 to 1.' },
  { name: 'Flow Duration', label: 'Flow duration', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Total Fwd Packets', label: 'Total fwd packets', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Total Backward Packets', label: 'Total backward packets', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Total Length of Fwd Packets', label: 'Total length of fwd packets', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Total Length of Bwd Packets', label: 'Total length of bwd packets', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Flow Bytes/s', label: 'Flow bytes/s', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Flow Packets/s', label: 'Flow packets/s', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Fwd Packet Length Mean', label: 'Fwd packet length mean', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Bwd Packet Length Mean', label: 'Bwd packet length mean', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'Flow IAT Mean', label: 'Flow IAT mean', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'SYN Flag Count', label: 'SYN flag count', kind: 'number', group: 'features', hint: 'Number.' },
  { name: 'ACK Flag Count', label: 'ACK flag count', kind: 'number', group: 'features', hint: 'Number.' },
] as const;

export const FIELD_GROUPS: readonly { id: FieldGroup; title: string; description: string }[] = [
  { id: 'identity', title: 'Identity', description: 'What the alert is and when it happened.' },
  { id: 'network', title: 'Network', description: 'The flow’s endpoints.' },
  { id: 'detector', title: 'Detector', description: 'What the first-stage detector said.' },
  { id: 'features', title: 'Flow features', description: 'The 12 flow statistics the triage agent is given.' },
];

export type FormValues = Record<string, string>;

export function emptyValues(): FormValues {
  return Object.fromEntries(ALERT_FIELDS.map((f) => [f.name, '']));
}

const ALERT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const FLOW_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?$/;
const INT_RE = /^[+-]?\d+$/;
const NUMBER_LIMIT = 1e15;

function isIpv4(v: string): boolean {
  const parts = v.split('.');
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function isIpv6(v: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(v) || !v.includes(':') || v.length > 45 || v.includes(':::')) return false;
  const doubles = v.split('::').length - 1;
  if (doubles > 1) return false;
  let text = v;
  const cut = v.lastIndexOf(':') + 1;
  if (v.slice(cut).includes('.')) {
    if (!isIpv4(v.slice(cut))) return false;
    text = `${v.slice(0, cut)}0:0`; // an embedded IPv4 address counts as two groups
  }
  const groups = text.split('::').flatMap((half) => (half === '' ? [] : half.split(':')));
  if (!groups.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  return doubles === 1 ? groups.length < 8 : groups.length === 8;
}

export function isIp(v: string): boolean {
  return isIpv4(v) || isIpv6(v);
}

function isRealTimestamp(v: string): string | null {
  const m = TIMESTAMP_RE.exec(v);
  if (!m) return 'Use the form YYYY-MM-DD HH:MM:SS, with no time zone.';
  const [year, month, day, hour, minute, second] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [number, number, number, number, number, number];
  if (year < 2000 || year > 2100) return 'The year must be between 2000 and 2100.';
  const d = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  const real = d.getUTCFullYear() === year && d.getUTCMonth() === month - 1 && d.getUTCDate() === day && hour < 24 && minute < 60 && second < 60;
  return real ? null : 'That is not a real date and time.';
}

function parseNumber(raw: string): number | null {
  const t = raw.trim();
  if (t === '' || !/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

/** null when the value is acceptable, otherwise a short message that names the rule (never the value). */
export function validateField(def: FieldDef, raw: string): string | null {
  const value = raw.trim();
  if (value === '') return 'Required.';
  switch (def.kind) {
    case 'alert_id': return ALERT_ID_RE.test(value) ? null : 'Use up to 64 letters, digits, . _ : - and start with a letter or digit.';
    case 'flow_id': return FLOW_ID_RE.test(value) ? null : 'Use up to 128 letters, digits, . _ : -';
    case 'timestamp': return isRealTimestamp(value);
    case 'ip': return isIp(value) ? null : 'Not a valid IPv4 or IPv6 address.';
    case 'port': {
      if (!INT_RE.test(value)) return 'Use a whole number.';
      const n = Number(value);
      return n >= 0 && n <= 65535 ? null : 'Must be from 0 to 65535.';
    }
    case 'protocol': {
      if (!INT_RE.test(value)) return 'Use a whole number.';
      const n = Number(value);
      return n >= 0 && n <= 255 ? null : 'Must be from 0 to 255.';
    }
    case 'score': {
      const n = parseNumber(value);
      if (n === null) return 'Use a number.';
      return n >= 0 && n <= 1 ? null : 'Must be from 0 to 1.';
    }
    case 'number': {
      const n = parseNumber(value);
      if (n === null) return 'Use a number.';
      return Math.abs(n) <= NUMBER_LIMIT ? null : 'That number is outside the accepted range.';
    }
  }
}

export function validateAll(values: FormValues): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const def of ALERT_FIELDS) {
    const message = validateField(def, values[def.name] ?? '');
    if (message) errors[def.name] = message;
  }
  return errors;
}

/** Typed alert object for the request body. Call only when validateAll() found no errors. */
export function toAlert(values: FormValues): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const def of ALERT_FIELDS) {
    const v = (values[def.name] ?? '').trim();
    switch (def.kind) {
      case 'port':
      case 'protocol': out[def.name] = Number.parseInt(v, 10); break;
      case 'score':
      case 'number': out[def.name] = Number(v); break;
      case 'timestamp': out[def.name] = v.replace('T', ' '); break;
      default: out[def.name] = v;
    }
  }
  return out;
}

export type ImportResult = { ok: true; values: FormValues; memory: 'off' | 'on' | null } | { ok: false; error: string };

/** Read pasted JSON: either the request body ({"alert": {...}, "memory": ...}) or just the alert object. Values stay as text so the form validates them. */
export function parseImportedJson(text: string): ImportResult {
  let data: unknown;
  try { data = JSON.parse(text); } catch { return { ok: false, error: 'That is not valid JSON.' }; }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return { ok: false, error: 'Expected a JSON object.' };
  let source = data as Record<string, unknown>;
  let memory: 'off' | 'on' | null = null;
  if ('alert' in source) {
    const extra = Object.keys(source).filter((k) => k !== 'alert' && k !== 'memory');
    if (extra.length) return { ok: false, error: `Only "alert" and "memory" are allowed at the top level (found ${extra.length} other${extra.length === 1 ? '' : 's'}).` };
    if (source.memory !== undefined) {
      if (source.memory !== 'off' && source.memory !== 'on') return { ok: false, error: '"memory" must be "off" or "on".' };
      memory = source.memory;
    }
    const inner = source.alert;
    if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) return { ok: false, error: '"alert" must be a JSON object.' };
    source = inner as Record<string, unknown>;
  }
  const known = new Set(ALERT_FIELDS.map((f) => f.name));
  const unknown = Object.keys(source).filter((k) => !known.has(k));
  if (unknown.length) return { ok: false, error: `The alert has ${unknown.length} field${unknown.length === 1 ? '' : 's'} that the API does not accept: ${unknown.slice(0, 5).join(', ')}${unknown.length > 5 ? ', …' : ''}.` };
  const values = emptyValues();
  for (const def of ALERT_FIELDS) {
    const v = source[def.name];
    if (v === undefined) continue;
    if (typeof v === 'string' || typeof v === 'number') values[def.name] = String(v);
    else return { ok: false, error: `"${def.name}" must be a text or number value.` };
  }
  return { ok: true, values, memory };
}

/** A made-up example for the "Insert example" button: reserved documentation addresses (RFC 5737), invented numbers, no real traffic. It is validated by the same rules as any other input. */
export const EXAMPLE_ALERT: Record<string, string | number> = {
  alert_id: 'EXAMPLE-0001', timestamp: '2026-01-15 09:30:00', flow_id: 'example-flow-1', src_ip: '198.51.100.23', src_port: 51514, dst_ip: '203.0.113.10', dst_port: 22, protocol: 6, detector_score: 0.87,
  'Flow Duration': 1200000, 'Total Fwd Packets': 14, 'Total Backward Packets': 9, 'Total Length of Fwd Packets': 840, 'Total Length of Bwd Packets': 620, 'Flow Bytes/s': 1216.7, 'Flow Packets/s': 19.2,
  'Fwd Packet Length Mean': 60, 'Bwd Packet Length Mean': 68.9, 'Flow IAT Mean': 52173.9, 'SYN Flag Count': 2, 'ACK Flag Count': 12,
};
