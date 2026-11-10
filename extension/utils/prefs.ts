// Настройки расширения: каждую новую функцию можно выключить. Хранятся в storage.local браузера.

export type Prefs = {
  /// значок Keywarden в полях логина и пароля
  icons: boolean;
  /// меню аккаунтов под полем при фокусе (иначе только по значку K)
  menuOnFocus: boolean;
  /// после входа предлагать сохранить или обновить пароль
  offerSave: boolean;
  /// после заполнения логина Keywarden сам вставит код 2FA на следующем шаге того же сайта
  autoOtp: boolean;
  /// сайты, где сохранять пароль не предлагаем никогда
  neverSites: string[];
};

export const DEFAULT_PREFS: Prefs = { icons: true, menuOnFocus: true, offerSave: true, autoOtp: true, neverSites: [] };

export async function loadPrefs(): Promise<Prefs> {
  const { prefs } = await browser.storage.local.get('prefs');
  return { ...DEFAULT_PREFS, ...(prefs ?? {}) };
}

export async function savePrefs(p: Prefs): Promise<void> {
  await browser.storage.local.set({ prefs: p });
}
