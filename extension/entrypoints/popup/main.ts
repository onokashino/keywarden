import { mount } from 'svelte';
import App from './App.svelte';
import { applyTheme, cachedTheme, type Theme } from '../../utils/theme';

document.documentElement.lang = browser.i18n.getUILanguage();

// сначала запомненная тема, потом свежая от демона
const paint = (t: Theme | null) => applyTheme(document.documentElement, t);
browser.storage.onChanged.addListener((c, area) => {
  if (area === 'local' && c.theme) paint((c.theme.newValue as Theme | undefined) ?? null);
});
browser.runtime.sendMessage({ type: 'theme' }).catch(() => {});

// окно рисуется уже в цветах темы, без перекрашивания на глазах
cachedTheme()
  .then(paint)
  .finally(() => mount(App, { target: document.getElementById('app')! }));
