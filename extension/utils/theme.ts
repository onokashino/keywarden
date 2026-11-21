// Тема приложения в расширении. Демон отдаёт цвета темы окна (ключи как в файле темы),
// здесь они становятся CSS-переменными --kw-*. В стилях у каждой переменной запасное значение
// встроенной темы, поэтому без демона и без своей темы всё выглядит как раньше.

export type Theme = { mode: string; colors: Record<string, string> };

const VARS: [string, string][] = [
  ['bg', 'background'],
  ['fg', 'foreground'],
  ['muted', 'muted.foreground'],
  ['border', 'border'],
  ['line', 'sidebar.border'],
  ['input-border', 'input.border'],
  ['surface', 'secondary.background'],
  ['surface-hover', 'secondary.hover.background'],
  ['sunken', 'sidebar.background'],
  ['segment', 'tab_bar.segmented.background'],
  ['active', 'list.active.background'],
  ['switch', 'switch.background'],
  ['thumb', 'scrollbar.thumb.background'],
  ['primary', 'primary.background'],
  ['primary-hover', 'primary.hover.background'],
  ['on-primary', 'primary.foreground'],
  ['accent', 'caret'],
  ['accent-hover', 'link.hover.foreground'],
  ['ring', 'ring'],
  ['danger', 'danger.background'],
  ['danger-fg', 'danger.foreground'],
  ['success', 'success.background'],
  ['success-fg', 'success.foreground'],
  ['warning', 'warning.background'],
  ['info-fg', 'info.foreground'],
];

const mix = (a: string, share: number, b: string) => `color-mix(in srgb, ${a} ${share}%, ${b})`;

export function themeVars(theme: Theme | null): Record<string, string> {
  const c = theme?.colors ?? {};
  const out: Record<string, string> = {};
  for (const [name, key] of VARS) if (c[key]) out[`--kw-${name}`] = c[key];
  const bg = c['background'];
  const fg = c['foreground'];
  const primary = c['primary.background'];
  // оттенков, которых в файле темы нет: смешиваем из её же цветов
  if (bg && fg) {
    out['--kw-fg-soft'] = mix(fg, 82, bg);
    out['--kw-fg-dim'] = mix(fg, 38, bg);
    out['--kw-border-strong'] = mix(fg, 22, bg);
    out['--kw-backdrop'] = mix(bg, 60, theme?.mode === 'light' ? '#888' : '#000');
  }
  if (bg && primary) {
    out['--kw-chip'] = mix(primary, 22, bg);
    out['--kw-chip-border'] = mix(primary, 60, bg);
  }
  return out;
}

export function applyTheme(el: HTMLElement, theme: Theme | null) {
  for (const p of Array.from(el.style)) if (p.startsWith('--kw-')) el.style.removeProperty(p);
  for (const [k, v] of Object.entries(themeVars(theme))) el.style.setProperty(k, v);
  if (theme && Object.keys(theme.colors).length) el.style.colorScheme = theme.mode === 'light' ? 'light' : 'dark';
}

/// последняя тема, которую отдал демон: чтобы окно не мигало встроенными цветами
export async function cachedTheme(): Promise<Theme | null> {
  return ((await browser.storage.local.get('theme')).theme as Theme | undefined) ?? null;
}
