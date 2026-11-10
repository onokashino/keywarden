// E2E расширения: headless Chromium + собранное расширение + настоящие keywarden-host и keywardend.
// Проверяет: подключение (ассоциация), выдачу пароля своему сайту и отказ чужому,
// заполнение формы, предложение сохранить новый пароль и само сохранение.
import { chromium } from 'playwright-core';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const EXT = path.resolve(process.argv[2]);
const HOST_BIN = path.resolve(process.argv[3]);
const assert = (cond, msg) => {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('ok:', msg);
};

const pages = {
  '/login': `<!doctype html><meta charset=utf-8><title>Вход</title>
    <form action="/welcome" method="get" style="margin:40px;display:grid;gap:8px;width:300px">
      <input id="user" name="username" autocomplete="username" placeholder="Логин">
      <input id="pass" name="password" type="password" autocomplete="current-password" placeholder="Пароль">
      <button type="submit">Войти</button>
    </form>`,
  '/login-otp': `<!doctype html><meta charset=utf-8><title>Вход с 2FA</title>
    <form action="/otp" method="get" style="margin:40px;display:grid;gap:8px;width:300px">
      <input id="user" name="username" autocomplete="username" placeholder="Логин">
      <input id="pass" name="password" type="password" autocomplete="current-password" placeholder="Пароль">
      <button type="submit">Войти</button>
    </form>`,
  '/otp': `<!doctype html><meta charset=utf-8><title>Код</title>
    <form action="/welcome" style="margin:40px;display:grid;gap:8px;width:300px">
      <label for="code">Код из приложения</label>
      <input id="code" name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6">
      <button type="submit">Подтвердить</button>
    </form>`,
  '/welcome': `<!doctype html><meta charset=utf-8><title>Добро пожаловать</title><p>ok</p>`,
  '/passkey': `<!doctype html><meta charset=utf-8><title>Passkey</title><script>
    const enc = (s) => new TextEncoder().encode(s);
    // DER (SEQUENCE{INTEGER r, INTEGER s}) → r||s по 32 байта для WebCrypto
    function derToRaw(der) {
      const d = new Uint8Array(der); let i = 2;
      const int = () => { i++; const len = d[i++]; let v = d.slice(i, i + len); i += len; while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
      const r = int(), s = int(); const raw = new Uint8Array(64); raw.set(r); raw.set(s, 32); return raw;
    }
    window.runPasskey = async () => {
      const cred = await navigator.credentials.create({ publicKey: {
        rp: { id: 'localhost', name: 'Local Test' }, user: { id: enc('user-1'), name: 'alice', displayName: 'Alice' },
        challenge: enc('reg-challenge'), pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } });
      const key = await crypto.subtle.importKey('spki', cred.response.getPublicKey(), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const a = await navigator.credentials.get({ publicKey: { rpId: 'localhost', challenge: enc('login-challenge'),
        allowCredentials: [{ type: 'public-key', id: cred.rawId }] } });
      const auth = new Uint8Array(a.response.authenticatorData);
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', a.response.clientDataJSON));
      const signed = new Uint8Array(auth.length + hash.length); signed.set(auth); signed.set(hash, auth.length);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(a.response.signature), signed);
      const cd = JSON.parse(new TextDecoder().decode(a.response.clientDataJSON));
      return { ok, instance: cred instanceof PublicKeyCredential && a instanceof PublicKeyCredential,
        sameId: cred.id === a.id, type: cd.type, origin: cd.origin, user: new TextDecoder().decode(a.response.userHandle) };
    };
  </script><p>passkey</p>`,
};
const server = http.createServer((req, res) => {
  const body = pages[new URL(req.url, 'http://x').pathname] ?? 'not found';
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(body);
});
await new Promise((r) => server.listen(8765, '127.0.0.1', r));
// второй сайт (другой хост) для входа с 2FA
const server2 = http.createServer(server.listeners('request')[0]);
await new Promise((r) => server2.listen(8765, '127.0.0.2', r));

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-chrome-'));
const ctx = await chromium.launchPersistentContext(profile, {
  executablePath: '/usr/bin/chromium',
  headless: true,
  // проверки ищут русские тексты интерфейса: язык Chromium (и расширения) русский
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-sandbox', '--lang=ru'],
  env: { ...process.env, LANGUAGE: 'ru', LANG: 'ru_RU.UTF-8' },
  locale: 'ru-RU',
});
let [sw] = ctx.serviceWorkers();
sw ??= await ctx.waitForEvent('serviceworker');
const extId = new URL(sw.url()).host;
console.log('расширение', extId);

// манифест native messaging для этого id (Chromium читает его при каждом connectNative)
// с собственным --user-data-dir Chromium ищет манифесты внутри профиля
for (const nmDir of [path.join(profile, 'NativeMessagingHosts'), path.join(os.homedir(), '.config/chromium/NativeMessagingHosts')]) {
  fs.mkdirSync(nmDir, { recursive: true });
  fs.writeFileSync(
    path.join(nmDir, 'dev.keywarden.host.json'),
    JSON.stringify({ name: 'dev.keywarden.host', description: 'Keywarden', path: HOST_BIN, type: 'stdio', allowed_origins: [`chrome-extension://${extId}/`] }),
  );
}

const popup = await ctx.newPage();
await popup.goto(`chrome-extension://${extId}/popup.html`);
const send = (msg) => popup.evaluate((m) => chrome.runtime.sendMessage(m), msg);

// 1. подключение
await popup.waitForTimeout(1500);
console.log('popup:', (await popup.innerText('body')).replace(/\n+/g, ' | '));
await popup.getByRole('button', { name: 'Подключить' }).click();
await popup.waitForFunction(() => !document.body.innerText.includes('Подключите расширение'), null, { timeout: 15000 });
const st = await send({ type: 'status' });
assert(st.ok && st.value.associated && !st.value.locked, `расширение подключено: ${JSON.stringify(st)}`);

// 2. заполнение на своём сайте
const site = await ctx.newPage();
await site.goto('http://127.0.0.1:8765/login');
await site.waitForTimeout(1500); // content script разобрал форму (WASM в background)
const tabId = await popup.evaluate(async () => (await chrome.tabs.query({ url: 'http://127.0.0.1:8765/*' }))[0].id);
const logins = await send({ type: 'logins', tabId });
assert(logins.ok && logins.value.length === 1 && logins.value[0].username === 'tester', `учётка для сайта найдена: ${JSON.stringify(logins)}`);
const fill = await send({ type: 'fill', id: logins.value[0].id, tabId });
assert(fill.ok, `заполнение разрешено: ${JSON.stringify(fill)}`);
await site.waitForTimeout(300);
assert((await site.inputValue('#user')) === 'tester', 'логин подставлен в форму');
assert((await site.inputValue('#pass')) === 'S3cret-from-db', 'пароль подставлен в форму');

// 3. чужой хост (localhost вместо 127.0.0.1) учётку не получает
const other = await ctx.newPage();
await other.goto('http://localhost:8765/login');
const otherTab = await popup.evaluate(async () => (await chrome.tabs.query({ url: 'http://localhost:8765/*' }))[0].id);
const none = await send({ type: 'logins', tabId: otherTab });
assert(none.ok && none.value.length === 0, 'чужому хосту учёток нет');
const steal = await send({ type: 'fill', id: logins.value[0].id, tabId: otherTab });
assert(!steal.ok, `пароль по известному id чужому хосту не отдан: ${steal.error}`);

// 4. новый логин: отправка формы → предложение сохранить → сохранение
await site.fill('#user', 'newuser');
await site.fill('#pass', 'Brand-new-pass-42');
await Promise.all([site.waitForURL('**/welcome**'), site.click('button[type=submit]')]);
await site.waitForTimeout(800);
const SHOTS = process.env.SHOTS;
if (SHOTS) {
  fs.mkdirSync(SHOTS, { recursive: true });
  await site.setViewportSize({ width: 900, height: 420 });
  await site.waitForTimeout(500);
  await site.screenshot({ path: `${SHOTS}/ext-save.png` });
}
const offer = await send({ type: 'pendingSave', tabId });
assert(offer.ok && offer.value?.username === 'newuser' && offer.value.state === 'new', `предложено сохранить: ${JSON.stringify(offer)}`);
const saved = await send({ type: 'save', accept: true, tabId });
assert(saved.ok, 'сохранено');
await site.goto('http://127.0.0.1:8765/login');
const after = await send({ type: 'logins', tabId });
assert(after.ok && after.value.some((l) => l.username === 'newuser' && l.group === 'Из браузера'), 'новая учётка в базе, папка «Из браузера»');

// 5. вход с 2FA: Keywarden заполнил логин → на странице кода код вставляется сам
async function otpFlow() {
  const p = await ctx.newPage();
  await p.goto('http://127.0.0.2:8765/login-otp');
  await p.waitForTimeout(1500);
  const tab = await popup.evaluate(async () => (await chrome.tabs.query({ url: 'http://127.0.0.2:8765/*' }))[0].id);
  const l = await send({ type: 'logins', tabId: tab });
  assert(l.ok && l.value.length === 1 && l.value[0].has_otp, `учётка с 2FA: ${JSON.stringify(l)}`);
  assert((await send({ type: 'fill', id: l.value[0].id, tabId: tab })).ok, 'логин с 2FA заполнен');
  await Promise.all([p.waitForURL('**/otp**'), p.click('button[type=submit]')]);
  await p.waitForTimeout(2500);
  const code = await p.inputValue('#code');
  await p.close();
  return code;
}
const code = await otpFlow();
assert(/^\d{6}$/.test(code), `код 2FA вставлен сам: ${code}`);
await popup.evaluate(() => chrome.storage.local.set({ prefs: { icons: true, offerSave: true, autoOtp: false, neverSites: [] } }));
assert((await otpFlow()) === '', 'с выключенной настройкой код не вставляется');
await popup.evaluate(() => chrome.storage.local.remove('prefs'));

// меню аккаунтов на сайте: фокус в поле → список, стрелка и Enter заполняют выбранный
await site.goto('http://127.0.0.1:8765/login');
await site.waitForTimeout(1500);
await site.click('#user');
await site.waitForTimeout(800);
assert((await site.locator('keywarden-menu').count()) === 1, 'меню аккаунтов открылось при фокусе');
if (process.env.SHOTS) await site.screenshot({ path: `${process.env.SHOTS}/ext-inline.png` });
await site.keyboard.press('ArrowDown');
await site.keyboard.press('Enter');
await site.waitForTimeout(800);
assert((await site.inputValue('#user')) === 'tester' && (await site.inputValue('#pass')) === 'S3cret-from-db', 'первым в меню последний использованный аккаунт (tester), форма заполнена');
assert((await site.locator('keywarden-menu').count()) === 0, 'меню закрылось после выбора');

// окно Keywarden панелью на странице (значок K): iframe с popup внутри скруглённой рамки
await site.goto('http://127.0.0.1:8765/login');
await site.waitForTimeout(1200);
await popup.evaluate((id) => chrome.tabs.sendMessage(id, { type: 'togglePanel' }), tabId);
await site.waitForTimeout(1800);
assert((await site.locator('keywarden-panel').count()) === 1, 'панель Keywarden открылась на странице');
if (process.env.SHOTS) {
  await site.setViewportSize({ width: 900, height: 640 });
  await site.waitForTimeout(600);
  await site.screenshot({ path: `${process.env.SHOTS}/ext-panel.png` });
}
await site.keyboard.press('Escape');
await site.waitForTimeout(400);
assert((await site.locator('keywarden-panel').count()) === 0, 'панель закрылась по Esc');

// popup: поиск по базе и карточка записи (без пароля, с кодом 2FA)
const found = await send({ type: 'search', query: 'OTP' });
assert(found.ok && found.value.some((l) => l.title === 'OTP site' && l.url === 'http://127.0.0.2:8765'), `поиск по базе: ${JSON.stringify(found)}`);
const facets = await send({ type: 'facets' });
assert(facets.ok && facets.value.folders.some((f) => f.name === 'SSH'), `папки для фильтра: ${JSON.stringify(facets.value?.folders?.map((f) => f.name))}`);
const ssh = await send({ type: 'search', query: '', filter: { kind: 'ssh_key' } });
assert(ssh.ok && ssh.value.length > 0 && ssh.value.every((l) => l.kind === 'ssh_key'), `фильтр по типу: ${ssh.value?.map((l) => l.title)}`);
const it = await send({ type: 'item', id: found.value.find((l) => l.title === 'OTP site').id });
assert(it.ok && it.value.has_password && /^\d{6}$/.test(it.value.totp[0]) && !JSON.stringify(it.value).includes('Otp-site-pass'), `карточка без пароля, с кодом: ${JSON.stringify(it.value)}`);

// 6. «никогда для сайта»: предложение больше не появляется
await site.goto('http://127.0.0.1:8765/login');
await site.waitForTimeout(1000);
await site.fill('#user', 'other');
await site.fill('#pass', 'Another-pass-77');
await Promise.all([site.waitForURL('**/welcome**'), site.click('button[type=submit]')]);
await site.waitForTimeout(800);
assert((await send({ type: 'neverSave', tabId })).ok, 'никогда для сайта');
await site.goto('http://127.0.0.1:8765/login');
await site.waitForTimeout(1000);
await site.fill('#user', 'third');
await site.fill('#pass', 'Third-pass-88');
await Promise.all([site.waitForURL('**/welcome**'), site.click('button[type=submit]')]);
await site.waitForTimeout(800);
const offer2 = await send({ type: 'pendingSave', tabId });
assert(offer2.ok && offer2.value === null, 'для сайта из списка «никогда» не предлагаем');

// 7. ключ доступа: регистрация и вход, подпись проверяет сама страница (как сервер)
const pk = await ctx.newPage();
await pk.goto('http://localhost:8765/passkey');
await pk.waitForTimeout(1000);
const res = await pk.evaluate(() => window.runPasskey());
assert(res.ok, `подпись входа ключом доступа верна (WebCrypto): ${JSON.stringify(res)}`);
assert(res.instance && res.sameId, 'объекты PublicKeyCredential, id совпадает');
assert(res.type === 'webauthn.get' && res.origin === 'http://localhost:8765', 'clientData: тип и origin страницы');
assert(res.user === 'user-1', 'userHandle возвращён');

// 8. кошелёк: в расширении только адреса, фраза не уходит ни в карточке, ни в буфер
const w = await send({ type: 'search', query: 'Cold' });
assert(w.ok && w.value.length === 1 && w.value[0].kind === 'crypto_wallet', `кошелёк находится поиском: ${JSON.stringify(w.value)}`);
const wi = await send({ type: 'item', id: w.value[0].id });
assert(
  wi.ok && wi.value.addresses.some((a) => a[1] === 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu') && !JSON.stringify(wi.value).includes('abandon') && !wi.value.has_password,
  `карточка кошелька: адрес есть, фразы нет: ${JSON.stringify(wi.value)}`,
);
for (const field of ['password', 'username', 'Seed']) {
  assert(!(await send({ type: 'copy', id: w.value[0].id, field })).ok, `кошелёк: «${field}» не копируется`);
}

// 9. генератор popup и поле нового пароля на сайте берут одни настройки
const g = await send({ type: 'generateWith', options: { mode: 'password', length: 32, lower: true, upper: true, digits: true, symbols: false, exclude_ambiguous: true } });
assert(g.ok && g.value.password.length === 32 && /^[A-Za-z0-9]+$/.test(g.value.password) && g.value.entropy > 150, `пароль 32 без символов: ${g.value?.password}`);
const gp = await send({ type: 'generateWith', options: { mode: 'passphrase', words: 5, separator: '-', capitalize: true, number: true } });
assert(gp.ok && gp.value.password.split('-').length === 5, `фраза из 5 слов: ${gp.value?.password}`);
const gs = await send({ type: 'generate' });
assert(gs.ok && gs.value.split('-').length === 5, `для сайта те же настройки (фраза): ${gs.value}`);

// 10. смена пароля: окно «Обновить пароль», глаз и кнопка нажимаются мышью (isTrusted)
const up = await ctx.newPage();
await up.setViewportSize({ width: 1280, height: 720 });
await up.goto('http://127.0.0.2:8765/login-otp');
await up.waitForTimeout(1500);
await up.fill('#user', 'otpuser');
await up.fill('#pass', 'Otp-site-NEW-1');
await Promise.all([up.waitForURL('**/otp**'), up.click('button[type=submit]')]);
await up.waitForTimeout(1500);
assert((await up.locator('keywarden-save').count()) === 1, 'окно «Обновить пароль» на странице');
await up.mouse.click(1238, 136); // глаз в строке пароля
await up.waitForTimeout(300);
if (SHOTS) await up.screenshot({ path: `${SHOTS}/ext-update.png`, clip: { x: 880, y: 0, width: 400, height: 240 } });
await up.mouse.click(1220, 182); // «Обновить»
await up.waitForTimeout(1000);
assert((await up.locator('keywarden-save').count()) === 0, 'окно закрылось после «Обновить»');
await up.goto('http://127.0.0.2:8765/login-otp');
await up.waitForTimeout(1500);
const upTab = await popup.evaluate(async () => (await chrome.tabs.query({ url: 'http://127.0.0.2:8765/*' }))[0].id);
const upL = await send({ type: 'logins', tabId: upTab });
assert(upL.ok && upL.value.length === 1, `после обновления учётка одна, без дубля: ${JSON.stringify(upL.value)}`);
await send({ type: 'fill', id: upL.value[0].id, tabId: upTab });
await up.waitForTimeout(400);
assert((await up.inputValue('#pass')) === 'Otp-site-NEW-1', 'в базе новый пароль');
await up.close();

if (SHOTS) {
  await popup.bringToFront();
  await popup.setViewportSize({ width: 392, height: 600 });
  await popup.reload();
  await popup.waitForTimeout(1200);
  await popup.screenshot({ path: `${SHOTS}/ext-popup.png` });
  await popup.getByTitle('Фильтры').click();
  await popup.waitForTimeout(300);
  await popup.locator('.trigger').nth(1).click();
  await popup.waitForTimeout(300);
  await popup.screenshot({ path: `${SHOTS}/ext-dropdown.png` });
  await popup.locator('.opt', { hasText: 'SSH' }).click();
  await popup.waitForTimeout(600);
  await popup.screenshot({ path: `${SHOTS}/ext-filtered.png` });
  await popup.reload();
  await popup.waitForTimeout(1200);
  await popup.locator('.item').first().getByTitle('Действия').click();
  await popup.waitForTimeout(300);
  await popup.screenshot({ path: `${SHOTS}/ext-popup-hover.png` });
  await popup.mouse.click(12, 580); // мимо меню: закрывается
  await popup.waitForTimeout(200);
  assert((await popup.locator('.pop').count()) === 0, 'меню «Действия» закрылось по щелчку мимо');
  await popup.getByRole('button', { name: 'Новая' }).click();
  await popup.waitForTimeout(600);
  await popup.screenshot({ path: `${SHOTS}/ext-new.png` });
  await popup.getByTitle('Назад').click();
  await popup.locator('.item', { hasText: 'OTP site' }).first().click();
  await popup.waitForTimeout(800);
  await popup.screenshot({ path: `${SHOTS}/ext-item.png` });
  await popup.getByTitle('Назад').click();
  await popup.getByRole('button', { name: 'Генератор' }).click();
  await popup.waitForTimeout(800);
  await popup.screenshot({ path: `${SHOTS}/ext-generator.png` });
  await popup.getByRole('button', { name: 'Фраза' }).click();
  await popup.waitForTimeout(600);
  await popup.screenshot({ path: `${SHOTS}/ext-generator-phrase.png` });
  await popup.getByRole('button', { name: 'Настройки' }).click();
  await popup.waitForTimeout(400);
  await popup.screenshot({ path: `${SHOTS}/ext-settings.png` });
}
// 11. блокировка из popup: дальше ни учёток, ни заполнения
assert((await send({ type: 'lock' })).ok, 'заблокировано из popup');
const st2 = await send({ type: 'status' });
assert(st2.ok && st2.value.locked, `статус: заблокировано: ${JSON.stringify(st2)}`);
const lockedL = await send({ type: 'logins', tabId });
assert(!lockedL.ok || lockedL.value.length === 0, `после блокировки учёток нет: ${JSON.stringify(lockedL)}`);
const lockedFill = await send({ type: 'fill', id: logins.value[0].id, tabId });
assert(!lockedFill.ok, `после блокировки заполнение отказано: ${lockedFill.error}`);

await ctx.close();
server.close();
server2.close();
console.log('E2E EXT OK');
