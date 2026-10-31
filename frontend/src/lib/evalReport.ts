// Reads the evaluation JSON the repository writes (python -m week5.evalrun.sensor_suite, or the formal evalrun report) defensively:
// anything that does not have the expected shape is not summarised, and the page falls back to the raw document. Numbers are only ever copied, never computed.

export interface ConfigRow { config: string; tp: number | null; fp: number | null; tn: number | null; fn: number | null; precision: number | null; recall: number | null; f1: number | null; specificity: number | null; fpr: number | null; fnr: number | null; flaggedRate: number | null; incorrectClosures: number | null; missed: string[] }
export interface ProfileView { name: string; assumption: string | null; rows: ConfigRow[]; ops: { label: string; value: string }[] }
export interface SensorEvalView {
  set: string | null; synthetic: boolean; fakeModel: boolean; generated: string | null; limits: string[]; violations: number;
  profiles: ProfileView[];
  providerFailure: { injected: number | null; fraction: number | null; allToReview: boolean | null; attacksClosed: number | null; confusion: ConfigRow | null } | null;
}

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

function row(config: string, c: Rec): ConfigRow {
  return {
    config, tp: num(c.tp), fp: num(c.fp), tn: num(c.tn), fn: num(c.fn), precision: num(c.precision), recall: num(c.recall), f1: num(c.f1), specificity: num(c.specificity),
    fpr: num(c.false_positive_rate), fnr: num(c.false_negative_rate), flaggedRate: num(c.flagged_rate), incorrectClosures: num(c.incorrect_closures_of_attacks), missed: strs(c.missed_attack_scenarios),
  };
}

function opsOf(o: unknown): { label: string; value: string }[] {
  if (!isRec(o)) return [];
  const out: { label: string; value: string }[] = [];
  for (const [k, v] of Object.entries(o)) {
    if (k === 'note') continue;
    if (typeof v === 'number' || typeof v === 'boolean') out.push({ label: k, value: String(v) });
    else if (isRec(v) && v.available === false) out.push({ label: k, value: `unavailable: ${str(v.reason) ?? 'no reason given'}` });
  }
  return out;
}

export function summariseSensorEval(content: unknown): SensorEvalView | null {
  if (!isRec(content) || !isRec(content.profiles)) return null;
  const profiles: ProfileView[] = [];
  for (const [name, p] of Object.entries(content.profiles)) {
    if (!isRec(p) || !isRec(p.configs)) return null;
    profiles.push({ name, assumption: str(p.assumption), rows: Object.entries(p.configs).filter(([, c]) => isRec(c)).map(([k, c]) => row(k, c as Rec)), ops: opsOf(p.ops) });
  }
  let providerFailure: SensorEvalView['providerFailure'] = null;
  if (isRec(content.provider_failure)) {
    const pf = content.provider_failure;
    providerFailure = {
      injected: num(pf.alerts_with_injected_outage), fraction: num(pf.injected_failure_fraction),
      allToReview: typeof pf.all_outage_cases_routed_to_review === 'boolean' ? pf.all_outage_cases_routed_to_review : null,
      attacksClosed: Array.isArray(pf.attacks_hit_and_closed) ? pf.attacks_hit_and_closed.length : null,
      confusion: isRec(pf.confusion_full_pipeline) ? row('full_pipeline', pf.confusion_full_pipeline) : null,
    };
  }
  return {
    set: str(content.set), synthetic: content.synthetic === true, fakeModel: content.fake_model === true, generated: str(content.generated_utc), limits: strs(content.limits),
    violations: Array.isArray(content.invariant_violations) ? content.invariant_violations.length : 0, profiles, providerFailure,
  };
}

export function formatRatio(v: number | null): string { return v === null ? '—' : v.toFixed(3); }
