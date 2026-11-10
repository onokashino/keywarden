import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-svelte'],
  manifestVersion: 3, // WXT по умолчанию собирает Firefox как MV2
  manifest: ({ browser }) => ({
    name: '__MSG_extName__',
    description: '__MSG_extDescription__',
    default_locale: 'en',
    // favicon: иконки сайтов в списке popup (только Chromium, в Firefox буква)
    // scripting: открыть панель на вкладке, открытой до установки или обновления расширения
    permissions: ['nativeMessaging', 'activeTab', 'storage', 'tabs', ...(browser === 'firefox' ? [] : ['favicon', 'scripting'])],
    // без wasm-unsafe-eval MV3 не даёт инстанцировать WASM
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
    // окно Keywarden открывается скруглённой панелью прямо на странице (iframe с popup.html)
    web_accessible_resources: [{ resources: ['popup.html'], matches: ['http://*/*', 'https://*/*'] }],
    commands: {
      'fill-login': {
        suggested_key: { default: 'Ctrl+Shift+L' },
        description: '__MSG_cmd_fill_login__',
      },
    },
    browser_specific_settings: {
      // ничего не собираем и никуда не отправляем
      gecko: { id: 'keywarden@onokashino.github.io', strict_min_version: '128.0', data_collection_permissions: { required: ['none'] } } as any,
    },
  }),
});
