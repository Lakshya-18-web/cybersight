import { useTheme } from '../../lib/theme';
import { Moon, Sun } from '../icons';
import { Button } from '../ui/Button';

/** Switches the whole application between the dark (default) and light theme. The choice lasts for this browser tab. */
export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const next = theme === 'dark' ? 'light' : 'dark';
  return <Button variant="ghost" size="sm" className="icon-btn theme-toggle" icon={theme === 'dark' ? Sun : Moon} aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`} aria-pressed={theme === 'light'} onClick={toggle} />;
}
