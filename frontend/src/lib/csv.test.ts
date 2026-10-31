import { describe, expect, it } from 'vitest';
import { csvCell, toCsv } from './csv';

describe('csvCell', () => {
  it('neutralises spreadsheet formulas', () => {
    for (const v of ['=SUM(A1)', '+1', '-1', '@x', '\tx']) expect(csvCell(v).startsWith("'")).toBe(true);
  });
  it('quotes commas, quotes and newlines, and leaves plain text alone', () => {
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('x\ny')).toBe('"x\ny"');
    expect(csvCell('PortScan')).toBe('PortScan');
  });
  it('writes null as an empty cell and numbers as text', () => { expect(csvCell(null)).toBe(''); expect(csvCell(0)).toBe('0'); });
});

describe('toCsv', () => {
  it('writes a header and one line per row, CRLF separated', () => {
    expect(toCsv([{ key: 'a', label: 'A' }, { key: 'b', label: 'B' }], [{ a: 1, b: '=x' }])).toBe("A,B\r\n1,'=x\r\n");
  });
});
