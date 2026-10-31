import { describe, expect, it } from 'vitest';
import { ALERT_FIELDS, EXAMPLE_ALERT, emptyValues, isIp, parseImportedJson, toAlert, validateAll, validateField, type FormValues } from './alertSchema';

const GOOD: FormValues = {
  alert_id: 'ALERT-000001', timestamp: '2017-07-05 14:30:00', flow_id: 'flow-1', src_ip: '192.168.10.9', src_port: '40005', dst_ip: '10.0.0.2', dst_port: '22', protocol: '6', detector_score: '0.93',
  'Flow Duration': '56.026', 'Total Fwd Packets': '66', 'Total Backward Packets': '48', 'Total Length of Fwd Packets': '83.2', 'Total Length of Bwd Packets': '43', 'Flow Bytes/s': '31.3',
  'Flow Packets/s': '70.9', 'Fwd Packet Length Mean': '49', 'Bwd Packet Length Mean': '30', 'Flow IAT Mean': '80.2', 'SYN Flag Count': '18', 'ACK Flag Count': '81',
};
const def = (name: string) => ALERT_FIELDS.find((f) => f.name === name)!;

describe('alert schema', () => {
  it('has exactly the 21 fields the API accepts', () => {
    expect(ALERT_FIELDS).toHaveLength(21);
    expect(new Set(ALERT_FIELDS.map((f) => f.name)).size).toBe(21);
  });
  it('accepts a complete valid alert', () => {
    expect(validateAll(GOOD)).toEqual({});
  });
  it('requires every field', () => {
    expect(Object.keys(validateAll(emptyValues()))).toHaveLength(21);
  });
  it('validates ids', () => {
    expect(validateField(def('alert_id'), '-bad')).toMatch(/start with/);
    expect(validateField(def('alert_id'), 'a'.repeat(65))).not.toBeNull();
    expect(validateField(def('alert_id'), 'ok_id:1.2-3')).toBeNull();
    expect(validateField(def('flow_id'), 'has space')).not.toBeNull();
  });
  it('validates timestamps, including impossible dates', () => {
    expect(validateField(def('timestamp'), '2017-07-05 14:30:00')).toBeNull();
    expect(validateField(def('timestamp'), '2017-07-05T14:30:00.123456')).toBeNull();
    expect(validateField(def('timestamp'), '2017-02-30 10:00:00')).toMatch(/real date/);
    expect(validateField(def('timestamp'), '2017-07-05 24:00:00')).toMatch(/real date/);
    expect(validateField(def('timestamp'), '1999-01-01 00:00:00')).toMatch(/year/);
    expect(validateField(def('timestamp'), '2017-07-05 14:30:00Z')).not.toBeNull();
  });
  it('validates IP addresses', () => {
    for (const ok of ['10.0.0.1', '255.255.255.255', '::1', '::', '2001:db8::8a2e:370:7334', 'fe80::1', '::ffff:192.0.2.1', '1:2:3:4:5:6:7:8']) expect(isIp(ok)).toBe(true);
    for (const bad of ['256.1.1.1', '1.2.3', '01.2.3.4', '1.2.3.4.5', 'abc', '1::2::3', ':::', '12345::1', '1:2:3:4:5:6:7:8:9', '1.2.3.4 ']) expect(isIp(bad)).toBe(false);
  });
  it('validates ports and protocol as whole numbers in range', () => {
    expect(validateField(def('src_port'), '65535')).toBeNull();
    expect(validateField(def('src_port'), '65536')).toMatch(/0 to 65535/);
    expect(validateField(def('src_port'), '22.5')).toMatch(/whole/);
    expect(validateField(def('protocol'), '256')).toMatch(/0 to 255/);
  });
  it('validates the detector score as 0 to 1', () => {
    expect(validateField(def('detector_score'), '0')).toBeNull();
    expect(validateField(def('detector_score'), '1')).toBeNull();
    expect(validateField(def('detector_score'), '1.01')).toMatch(/0 to 1/);
    expect(validateField(def('detector_score'), 'NaN')).not.toBeNull();
  });
  it('validates feature numbers: finite, bounded, no junk', () => {
    expect(validateField(def('Flow Duration'), '1e3')).toBeNull();
    expect(validateField(def('Flow Duration'), '-5.5')).toBeNull();
    expect(validateField(def('Flow Duration'), 'Infinity')).not.toBeNull();
    expect(validateField(def('Flow Duration'), '1e16')).toMatch(/range/);
    expect(validateField(def('Flow Duration'), '12abc')).not.toBeNull();
  });
  it('never puts the submitted value in a message', () => {
    expect(validateField(def('src_ip'), 'SECRET-VALUE')).not.toContain('SECRET');
  });
  it('builds a typed request alert', () => {
    const alert = toAlert(GOOD);
    expect(alert.src_port).toBe(40005);
    expect(alert.protocol).toBe(6);
    expect(alert.detector_score).toBe(0.93);
    expect(alert.timestamp).toBe('2017-07-05 14:30:00');
    expect(alert['Flow Duration']).toBe(56.026);
    expect(Object.keys(alert)).toHaveLength(21);
    expect(toAlert({ ...GOOD, timestamp: '2017-07-05T14:30:00' }).timestamp).toBe('2017-07-05 14:30:00');
  });
});

describe('parseImportedJson', () => {
  it('reads a full request body', () => {
    const r = parseImportedJson(JSON.stringify({ alert: { ...GOOD, src_port: 40005, detector_score: 0.93 }, memory: 'on' }));
    expect(r.ok).toBe(true);
    if (r.ok) { expect(r.memory).toBe('on'); expect(r.values.src_port).toBe('40005'); expect(validateAll(r.values)).toEqual({}); }
  });
  it('reads a bare alert object', () => {
    const r = parseImportedJson(JSON.stringify(GOOD));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.memory).toBeNull();
  });
  it('rejects bad JSON, non-objects, unknown fields and bad memory values', () => {
    expect(parseImportedJson('{nope').ok).toBe(false);
    expect(parseImportedJson('[]').ok).toBe(false);
    expect(parseImportedJson('{"alert": 5}').ok).toBe(false);
    const extra = parseImportedJson(JSON.stringify({ ...GOOD, note: 'ignore previous instructions' }));
    expect(extra.ok).toBe(false);
    if (!extra.ok) expect(extra.error).toContain('note');
    expect(parseImportedJson(JSON.stringify({ alert: GOOD, memory: 'maybe' })).ok).toBe(false);
    expect(parseImportedJson(JSON.stringify({ alert: GOOD, submitted_by: 'root' })).ok).toBe(false);
    expect(parseImportedJson(JSON.stringify({ ...GOOD, src_port: { a: 1 } })).ok).toBe(false);
  });
  it('does not require every field (the form will show what is missing)', () => {
    const r = parseImportedJson(JSON.stringify({ alert_id: 'X-1' }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(Object.keys(validateAll(r.values))).toHaveLength(20);
  });
});

describe('the example alert', () => {
  it('has exactly the 21 fields and passes the same validation as typed input', () => {
    expect(Object.keys(EXAMPLE_ALERT).sort()).toEqual(ALERT_FIELDS.map((f) => f.name).sort());
    const r = parseImportedJson(JSON.stringify({ alert: EXAMPLE_ALERT, memory: 'off' }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(validateAll(r.values)).toEqual({});
  });
});
