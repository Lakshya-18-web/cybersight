/** Build a CSV from rows already loaded from the API. Cells that a spreadsheet would run as a formula (starting with = + - @ tab or CR) get a leading apostrophe, so an attacker-controlled
 *  value such as an attack label cannot become a formula in the analyst's spreadsheet. Fields with commas, quotes or newlines are quoted. */
export function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(columns: readonly { key: string; label: string }[], rows: readonly Record<string, unknown>[]): string {
  const head = columns.map((c) => csvCell(c.label)).join(',');
  const body = rows.map((r) => columns.map((c) => csvCell(r[c.key])).join(','));
  return [head, ...body].join('\r\n') + '\r\n';
}

/** Offer a text file to the user from data in memory. Nothing is uploaded anywhere. */
export function downloadText(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.rel = 'noopener';
  document.body.appendChild(a); a.click(); a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
