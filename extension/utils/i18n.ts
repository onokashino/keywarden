// Строки интерфейса из public/_locales: язык берётся у браузера, по умолчанию en.
// Тип ключа WXT выводит из messages.json: опечатка в ключе ловится на svelte-check.
type Key = Parameters<typeof browser.i18n.getMessage>[0];

export function t(key: Key, ...subs: (string | number)[]): string {
  return browser.i18n.getMessage(key, subs.map(String)) || key;
}
