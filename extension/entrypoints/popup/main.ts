import { mount } from 'svelte';
import App from './App.svelte';
import { applyTheme, cachedTheme, type Theme } from '../../utils/theme';

document.documentElement.lang = browser.i18n.getUILanguage();

// сначала запомненная тема, потом свежая от демона
const paint = (t: Theme | null) => applyTheme(document.documentElement, t);
browser.storage.onChanged.addListener((c, area) => {
  if (area === 'local' && c.theme) paint((c.theme.newValue as Theme | undefined) ?? null);
});

// панель на странице сначала подтверждает фону, что её открыли по щелчку на значке, а не встроил сайт
const auth =
  location.hash === '#panel' && parent !== window
    ? new Promise<void>((done) => {
        addEventListener('message', function on(e) {
          if (e.source !== parent || typeof e.data?.kwToken !== 'string') return;
          removeEventListener('message', on);
          browser.runtime.sendMessage({ type: 'panelAuth', token: e.data.kwToken }).catch(() => {}).finally(done);
        });
        parent.postMessage({ kw: 'panel-ready' }, '*');
      })
    : Promise.resolve();

auth.then(() => {
  browser.runtime.sendMessage({ type: 'theme' }).catch(() => {});
  // окно рисуется уже в цветах темы, без перекрашивания на глазах
  cachedTheme()
    .then(paint)
    .finally(() => mount(App, { target: document.getElementById('app')! }));
});
