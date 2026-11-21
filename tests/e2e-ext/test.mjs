// E2E расширения: headless Chromium + собранное расширение + настоящие keywarden-host и keywardend.
// Проверяет: подключение (ассоциация), выдачу пароля своему сайту и отказ чужому,
// заполнение формы, предложение сохранить новый пароль и само сохранение.
import { chromium } from 'playwright-core';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

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
  '/pay': `<!doctype html><meta charset=utf-8><title>Оплата</title>
    <form action="/welcome" style="margin:40px;display:grid;gap:8px;width:300px">
      <input id="fname" name="first_name" placeholder="Имя">
      <input id="lname" name="last_name" placeholder="Фамилия">
      <input id="mail" name="email" type="email" placeholder="Почта">
      <input id="city" name="city" placeholder="Город">
      <select id="country" name="country"><option value="">-</option><option value="DE">Germany</option><option value="RU">Russia</option></select>
      <input id="ccname" name="cardholder" placeholder="Имя на карте">
      <input id="ccnum" name="cardnumber" inputmode="numeric" placeholder="Номер карты">
      <select id="mm" name="exp_month"><option value="">MM</option>${[...Array(12)].map((_, i) => `<option value="${i + 1}">${String(i + 1).padStart(2, '0')}</option>`).join('')}</select>
      <select id="yy" name="exp_year"><option value="">YY</option><option value="2026">26</option><option value="2029">29</option></select>
      <input id="exp" autocomplete="cc-exp" placeholder="MM/YY" maxlength="5">
      <input id="cvc" name="cvc" type="password" maxlength="4" placeholder="CVC">
      <button type="submit">Оплатить</button>
    </form>`,
  '/signup': `<!doctype html><meta charset=utf-8><title>Регистрация</title>
    <form action="/welcome" method="get" style="margin:40px;display:grid;gap:8px;width:300px">
      <input id="user" name="login" autocomplete="username" placeholder="Логин">
      <input id="p1" name="password" type="password" autocomplete="new-password" placeholder="Пароль">
      <input id="p2" name="password2" type="password" autocomplete="new-password" placeholder="Ещё раз">
      <button type="submit">Создать</button>
    </form>`,
  '/odd': `<!doctype html><meta charset=utf-8><title>Странная форма</title>
    <div style="margin:40px;display:grid;gap:8px;width:300px">
      <input id="a" name="field_a" placeholder="Кто вы">
      <input id="b" name="field_b" type="password" placeholder="Секрет">
    </div>`,
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
const cards = await send({ type: 'search', query: '', filter: { kind: 'card' } });
assert(cards.ok && cards.value.length > 0 && cards.value.every((l) => l.kind === 'card'), `фильтр по типу: ${cards.value?.map((l) => l.title)}`);
// ключи и серверы SSH в браузере не нужны: расширению они не отдаются вовсе
const everything = await send({ type: 'search', query: '' });
assert(everything.ok && !everything.value.some((l) => ['ssh_key', 'ssh_host'].includes(l.kind)), `в списке расширения нет SSH: ${everything.value?.map((l) => l.kind)}`);
// заметка открывается с текстом
const noteHit = everything.value.find((l) => l.kind === 'note' && l.title === 'Recovery codes');
assert(noteHit, `заметка в списке: ${everything.value.map((l) => l.title)}`);
const noteItem = await send({ type: 'item', id: noteHit.id });
assert(noteItem.ok && noteItem.value.notes === '1111-2222', `текст заметки в карточке: ${JSON.stringify(noteItem.value)}`);
assert((await send({ type: 'search', query: 'github ssh' })).value.every((l) => l.kind !== 'ssh_key'), 'ключ SSH не находится и поиском');
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
  await popup.setViewportSize({ width: 460, height: 600 });
  await popup.reload();
  await popup.waitForTimeout(1200);
  await popup.screenshot({ path: `${SHOTS}/ext-popup.png` });
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
  // единственная запись в списке стоит у верхнего края: меню должно открыться вниз и не обрезаться
  const inside = async () => popup.evaluate(() => {
    const p = document.querySelector('.pop').getBoundingClientRect();
    const b = document.querySelector('.pop').closest('.scroll').getBoundingClientRect();
    return p.top >= b.top && p.bottom <= b.bottom;
  });
  await popup.getByPlaceholder('Поиск в хранилище').fill('Cold');
  await popup.waitForTimeout(700);
  await popup.locator('.item').first().getByTitle('Действия').click();
  await popup.waitForTimeout(300);
  assert(await inside(), 'меню единственной записи целиком видно');
  await popup.screenshot({ path: `${SHOTS}/ext-menu-single.png` });
  await popup.mouse.click(12, 580);
  await popup.getByPlaceholder('Поиск в хранилище').fill('');
  await popup.waitForTimeout(700);
  // удаление: первое нажатие переспрашивает, второе убирает запись в корзину
  const before = (await send({ type: 'search', query: '' })).value.length;
  await popup.getByPlaceholder('Поиск в хранилище').fill('Throwaway');
  await popup.waitForTimeout(700);
  await popup.locator('.item').first().getByTitle('Действия').click();
  await popup.getByRole('menuitem', { name: 'Удалить' }).click();
  await popup.waitForTimeout(200);
  assert((await send({ type: 'search', query: '' })).value.length === before, 'после первого нажатия запись на месте');
  await popup.screenshot({ path: `${SHOTS}/ext-delete.png` });
  await popup.getByRole('menuitem', { name: /Да, удалить/ }).click();
  await popup.waitForTimeout(1500);
  assert((await send({ type: 'search', query: '' })).value.length === before - 1, 'после второго нажатия запись ушла из списка');
  await popup.getByPlaceholder('Поиск в хранилище').fill('');
  await popup.waitForTimeout(700);
  // последняя запись длинного списка: меню открывается вверх
  await popup.locator('.item').last().scrollIntoViewIfNeeded();
  await popup.locator('.item').last().getByTitle('Действия').click();
  await popup.waitForTimeout(300);
  assert(await inside(), 'меню последней записи целиком видно');
  await popup.mouse.click(12, 300);
  await popup.waitForTimeout(200);
  await popup.getByRole('button', { name: 'Новая' }).click();
  await popup.waitForTimeout(600);
  await popup.screenshot({ path: `${SHOTS}/ext-new.png` });
  await popup.getByTitle('Назад').click();
  await popup.locator('.item', { hasText: 'OTP site' }).first().click();
  await popup.waitForTimeout(800);
  await popup.screenshot({ path: `${SHOTS}/ext-item.png` });
  await popup.getByTitle('Назад').click();
  await popup.locator('.item', { hasText: 'Recovery codes' }).first().click();
  await popup.waitForTimeout(800);
  await popup.screenshot({ path: `${SHOTS}/ext-note.png` });
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
// значок в поле прячется, когда форму закрыло окно поверх неё
const cov = await ctx.newPage();
await cov.goto('http://127.0.0.2:8765/login-otp');
await cov.waitForTimeout(1500);
const shownIcons = () => cov.evaluate(() => [...document.querySelectorAll('keywarden-icon')].filter((h) => h.style.display !== 'none').length);
assert((await shownIcons()) === 2, 'значки в полях логина и пароля');
await cov.evaluate(() => {
  const d = document.createElement('div');
  d.style.cssText = 'position:fixed;inset:0;background:#000c;z-index:1000';
  document.body.appendChild(d);
});
await cov.waitForTimeout(900);
assert((await shownIcons()) === 0, 'под окном поверх формы значков не видно');
await cov.close();

// 10a. карта (из kpxc-full.xml) и личные данные: меню под полем, стрелка и Enter заполняют всю группу полей
const pay = await ctx.newPage();
await pay.setViewportSize({ width: 1280, height: 900 });
await pay.goto('http://localhost:8765/pay');
await pay.waitForTimeout(1500);
await pay.click('#ccnum');
await pay.waitForTimeout(700);
assert((await pay.locator('keywarden-menu').count()) === 1, 'меню карт под полем номера');
if (SHOTS) await pay.screenshot({ path: `${SHOTS}/ext-card-menu.png`, clip: { x: 0, y: 0, width: 520, height: 560 } });
await pay.keyboard.press('ArrowDown');
await pay.keyboard.press('Enter');
await pay.waitForTimeout(1200);
const cardVals = await pay.evaluate(() => Object.fromEntries(['ccname', 'ccnum', 'mm', 'yy', 'exp', 'cvc', 'fname'].map((i) => [i, document.getElementById(i).value])));
assert(
  cardVals.ccname === 'IVAN IVANOV' && cardVals.ccnum === '4111111111111111' && cardVals.mm === '12' && cardVals.yy === '2029' && cardVals.exp === '12/29' && cardVals.cvc === '123',
  `карта заполнена, срок в виде каждого поля: ${JSON.stringify(cardVals)}`,
);
assert(cardVals.fname === '', 'личные данные вместе с картой не заполняются');
await pay.click('#fname');
await pay.waitForTimeout(700);
assert((await pay.locator('keywarden-menu').count()) === 1, 'меню личных данных под полем имени');
await pay.keyboard.press('ArrowDown');
await pay.keyboard.press('Enter');
await pay.waitForTimeout(1200);
const idVals = await pay.evaluate(() => Object.fromEntries(['fname', 'lname', 'mail', 'city', 'country'].map((i) => [i, document.getElementById(i).value])));
assert(
  idVals.fname === 'Ivan' && idVals.lname === 'Petrov' && idVals.mail === 'ivan@example.com' && idVals.city === 'Kazan' && idVals.country === 'RU',
  `личные данные заполнены, страна выбрана в списке: ${JSON.stringify(idVals)}`,
);

// 10b. меню по правой кнопке мыши: вход в форме, которую Keywarden сам не распознал
await send({ type: 'create', title: 'Odd', username: 'odd-user', password: 'Odd-pass-1', url: 'http://127.0.0.3:8765' });
const server3 = http.createServer(server.listeners('request')[0]);
await new Promise((r) => server3.listen(8765, '127.0.0.3', r));
const odd = await ctx.newPage();
await odd.goto('http://127.0.0.3:8765/odd');
await odd.waitForTimeout(1500);
await odd.click('#b', { button: 'right' });
const oddTab = await popup.evaluate(async () => (await chrome.tabs.query({ url: 'http://127.0.0.3:8765/*' }))[0]);
// сам щелчок по меню браузера из теста не сделать: вызываем обработчик пункта в фоне расширения
await sw.evaluate((tab) => chrome.contextMenus.onClicked.dispatch({ menuItemId: 'kw-fill', frameId: 0, editable: true }, tab), oddTab);
await odd.waitForTimeout(1500);
assert((await odd.inputValue('#a')) === 'odd-user' && (await odd.inputValue('#b')) === 'Odd-pass-1', `«Заполнить логин и пароль» по правой кнопке: ${await odd.inputValue('#a')}`);
await odd.click('#a', { button: 'right' });
await sw.evaluate((tab) => chrome.contextMenus.onClicked.dispatch({ menuItemId: 'kw-generate', frameId: 0, editable: true }, tab), oddTab);
await odd.waitForTimeout(1000);
assert((await odd.inputValue('#a')).length >= 12 && (await odd.inputValue('#a')) !== 'odd-user', `«Сгенерировать пароль» вставил в поле под курсором: ${await odd.inputValue('#a')}`);

// 10c. заполнение при открытии страницы: выключено по умолчанию, включённое заполняет разрешённый сайт
await odd.goto('http://127.0.0.2:8765/login-otp');
await odd.waitForTimeout(1500);
assert((await odd.inputValue('#pass')) === '', 'по умолчанию при открытии ничего не заполняется');
await popup.evaluate(() => chrome.storage.local.set({ prefs: { fillOnLoad: true } }));
await odd.goto('http://127.0.0.2:8765/login-otp');
await odd.waitForTimeout(2000);
assert((await odd.inputValue('#user')) === 'otpuser' && (await odd.inputValue('#pass')) === 'Otp-site-NEW-1', `заполнено при открытии: ${await odd.inputValue('#user')}`);
await popup.evaluate(() => chrome.storage.local.remove('prefs'));

// 10d. регистрация: сгенерированный пароль в оба поля, после отправки предложение сохранить, логин правится в окне
const reg = await ctx.newPage();
await reg.setViewportSize({ width: 1280, height: 720 });
await reg.goto('http://localhost:8765/signup');
await reg.waitForTimeout(1500);
await reg.fill('#user', 'newbie');
await reg.click('#p1');
await reg.waitForTimeout(900);
await reg.keyboard.press('ArrowDown');
await reg.keyboard.press('Enter');
await reg.waitForTimeout(500);
const genPw = await reg.inputValue('#p1');
assert(genPw.length >= 12 && (await reg.inputValue('#p2')) === genPw, `новый пароль в обоих полях: ${genPw}`);
await Promise.all([reg.waitForURL('**/welcome**'), reg.press('#p2', 'Enter')]);
await reg.waitForTimeout(1500);
const regTab = await popup.evaluate(async () => (await chrome.tabs.query({})).find((t) => t.url.includes('login=newbie')).id);
const regOffer = await send({ type: 'pendingSave', tabId: regTab });
assert(regOffer.ok && regOffer.value?.state === 'new' && regOffer.value.password === genPw, `после регистрации предложено сохранить: ${JSON.stringify(regOffer)}`);
await reg.mouse.click(1200, 93); // поле логина в окне: дописываем
await reg.keyboard.press('End');
await reg.keyboard.type('@mail');
if (SHOTS) await reg.screenshot({ path: `${SHOTS}/ext-save-edit.png`, clip: { x: 880, y: 0, width: 400, height: 240 } });
await reg.mouse.click(1220, 182); // «Сохранить»
await reg.waitForTimeout(1200);
const regLogins = await send({ type: 'logins', tabId: regTab });
assert(regLogins.ok && regLogins.value.some((l) => l.username === 'newbie@mail'), `сохранено с исправленным логином: ${JSON.stringify(regLogins)}`);

// 11. блокировка из popup: дальше ни учёток, ни заполнения
assert((await send({ type: 'lock' })).ok, 'заблокировано из popup');
const st2 = await send({ type: 'status' });
assert(st2.ok && st2.value.locked, `статус: заблокировано: ${JSON.stringify(st2)}`);
const lockedL = await send({ type: 'logins', tabId });
assert(!lockedL.ok || lockedL.value.length === 0, `после блокировки учёток нет: ${JSON.stringify(lockedL)}`);
const lockedFill = await send({ type: 'fill', id: logins.value[0].id, tabId });
assert(!lockedFill.ok, `после блокировки заполнение отказано: ${lockedFill.error}`);

// 12. вход при заблокированной базе: предложение не теряется, после разблокировки обычное «Сохранить»
// сайт просит ключ доступа при заблокированной базе: окно «разблокировать», после разблокировки вход продолжается сам
await pk.bringToFront();
await pk.evaluate(() => {
  window.lockedGet = navigator.credentials
    .get({ publicKey: { rpId: 'localhost', challenge: new TextEncoder().encode('locked-challenge') } })
    .then((a) => new TextDecoder().decode(a.response.userHandle), (e) => `error: ${e.message}`);
});
await pk.waitForTimeout(1000);
assert((await pk.locator('keywarden-menu').count()) === 1, 'ключ доступа при блокировке: окно с «Разблокировать»');
if (SHOTS) await pk.screenshot({ path: `${SHOTS}/ext-passkey-locked.png` });
await pk.mouse.click(646, 128); // «Разблокировать Keywarden»
await pk.waitForTimeout(300);
assert((await pk.locator('keywarden-menu').count()) === 0, 'окно закрылось, ждём разблокировки');
const lk = await ctx.newPage();
await lk.setViewportSize({ width: 1280, height: 720 });
await lk.goto('http://localhost:8765/login'); // 127.0.0.1 выше попал в «никогда для сайта»
await lk.waitForTimeout(1500);
await lk.fill('#user', 'while-locked');
await lk.fill('#pass', 'Locked-new-1');
// под полем висит меню «Разблокировать» и закрывает кнопку: отправляем по Enter
await Promise.all([lk.waitForURL('**/welcome**'), lk.press('#pass', 'Enter')]);
await lk.waitForTimeout(1500);
const lkTab = await popup.evaluate(async () => (await chrome.tabs.query({})).find((t) => t.url.includes('while-locked')).id);
const lockedOffer = await send({ type: 'pendingSave', tabId: lkTab });
assert(lockedOffer.ok && lockedOffer.value.state === 'locked' && !lockedOffer.value.password, `предложение ждёт разблокировки: ${JSON.stringify(lockedOffer)}`);
assert((await lk.locator('keywarden-save').count()) === 1, 'окно «Разблокируйте, чтобы сохранить» на странице');
if (SHOTS) await lk.screenshot({ path: `${SHOTS}/ext-locked-save.png`, clip: { x: 880, y: 0, width: 400, height: 240 } });
await lk.mouse.click(1187, 123); // «Разблокировать»: окна нет (headless), базу открывает kw
execFileSync(path.join(path.dirname(HOST_BIN), 'kw'), ['unlock', '--password-stdin'], { input: 't\n' });
await lk.waitForTimeout(2500);
const openOffer = await send({ type: 'pendingSave', tabId: lkTab });
assert(openOffer.ok && openOffer.value.state === 'new' && openOffer.value.password === 'Locked-new-1', `после разблокировки обычное предложение: ${JSON.stringify(openOffer)}`);
assert((await lk.locator('keywarden-save').count()) === 1, 'окно «Сохранить пароль» после разблокировки');
const lockedUser = await pk.evaluate(() => Promise.race([window.lockedGet, new Promise((r) => setTimeout(() => r('timeout'), 8000))]));
assert(lockedUser === 'user-1', `после разблокировки вход ключом доступа продолжился: ${lockedUser}`);
if (SHOTS) await lk.screenshot({ path: `${SHOTS}/ext-locked-save-after.png`, clip: { x: 880, y: 0, width: 400, height: 240 } });

await ctx.close();
server.close();
server2.close();
server3.close();
console.log('E2E EXT OK');
