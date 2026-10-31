/** Collapsed JSON for data the UI does not interpret (evidence payloads, parameters). Rendered as text, never as HTML. */
export function JsonView({ value, label = 'Show raw data' }: { value: unknown; label?: string }) {
  let text: string;
  try { text = JSON.stringify(value, null, 2) ?? ''; } catch { text = String(value); }
  return (
    <details className="details">
      <summary>{label}</summary>
      <pre className="codeblock">{text}</pre>
    </details>
  );
}
