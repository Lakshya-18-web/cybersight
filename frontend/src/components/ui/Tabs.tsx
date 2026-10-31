import { useRef, type KeyboardEvent } from 'react';

export interface TabDef { id: string; label: string; count?: number | null }

/** Accessible tabs: arrow keys, Home and End move between them (focus and selection together). Render the panel yourself with role="tabpanel" and aria-labelledby={tabId(prefix, id)}. */
export function tabId(prefix: string, id: string): string { return `${prefix}-tab-${id}`; }
export function panelId(prefix: string, id: string): string { return `${prefix}-panel-${id}`; }

export function Tabs({ tabs, value, onChange, prefix, label }: { tabs: readonly TabDef[]; value: string; onChange: (id: string) => void; prefix: string; label: string }) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const onKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next = -1;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    if (next === -1) return;
    event.preventDefault();
    const target = tabs[next];
    if (target) { onChange(target.id); refs.current[target.id]?.focus(); }
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, i) => (
        <button
          key={tab.id}
          ref={(el) => { refs.current[tab.id] = el; }}
          type="button"
          role="tab"
          className="tab"
          id={tabId(prefix, tab.id)}
          aria-selected={tab.id === value}
          {...(tab.id === value ? { 'aria-controls': panelId(prefix, tab.id) } : {})}
          tabIndex={tab.id === value ? 0 : -1}
          onClick={() => onChange(tab.id)}
          onKeyDown={(e) => onKey(e, i)}
        >
          {tab.label}{tab.count !== undefined && tab.count !== null ? <span className="muted num"> ({tab.count})</span> : null}
        </button>
      ))}
    </div>
  );
}
