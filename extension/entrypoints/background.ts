// Тонкая обёртка: вся логика (шифрование канала, классификация полей) в Rust/WASM
// (crates/keywarden-ext), решения о выдаче паролей принимает демон.
// WASM загружается только здесь, не в content script, и не выставляется сайтам.
import initWasm, { classifyFields, generateKeypair, open, seal } from '../wasm/keywarden_ext';
import type { FieldInfo, Login, Msg, PendingSave, Reply, Status } from '../utils/messages';
import { loadPrefs, savePrefs } from '../utils/prefs';
import { t } from '../utils/i18n';

const HOST = 'dev.keywarden.host';

type Keys = { clientId: string; public: string; secret: string; serverPublic?: string };

export default defineBackground(() => {
  const ready = initWasm({ module_or_path: browser.runtime.getURL('/keywarden_ext_bg.wasm') });

  // --- ключи расширения (храним локально, секрет не покидает расширение) ---
  async function keys(): Promise<Keys> {
    const { keywarden } = (await browser.storage.local.get('keywarden')) as { keywarden?: Keys };
    if (keywarden?.secret) return keywarden;
    await ready;
    const kp = JSON.parse(generateKeypair());
    const k: Keys = { clientId: crypto.randomUUID(), public: kp.public, secret: kp.secret };
    await browser.storage.local.set({ keywarden: k });
    return k;
  }

  // --- порт к keywarden-host: ответы приходят строго по порядку ---
  let port: Browser.runtime.Port | null = null;
  let queue: { resolve: (v: any) => void; reject: (e: Error) => void }[] = [];

  function connect(): Browser.runtime.Port {
    if (port) return port;
    const p = browser.runtime.connectNative(HOST);
    p.onMessage.addListener((m) => queue.shift()?.resolve(m));
    p.onDisconnect.addListener(() => {
      const err = new Error(browser.runtime.lastError?.message ?? t('err_host_disconnected'));
      queue.splice(0).forEach((q) => q.reject(err));
      port = null;
    });
    port = p;
    return p;
  }

  function send(message: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      queue.push({ resolve, reject });
      try {
        connect().postMessage(message);
      } catch (e) {
        queue.pop();
        reject(e as Error);
      }
    });
  }

  class DaemonError extends Error {
    constructor(public code: string, message: string) {
      super(message);
    }
  }

  async function associate(): Promise<void> {
    const k = await keys();
    const r = await send({ type: 'associate', client_id: k.clientId, client_public: k.public, name: t('client_name', import.meta.env.BROWSER) });
    if (r.type !== 'associated') throw new DaemonError(r.code ?? 'error', r.message ?? t('err_connect_failed'));
    await browser.storage.local.set({ keywarden: { ...k, serverPublic: r.server_public } });
  }

  /// Зашифрованный запрос к демону.
  async function call(action: Record<string, unknown>): Promise<any> {
    await ready;
    const k = await keys();
    if (!k.serverPublic) throw new DaemonError('not_associated', t('err_not_associated'));
    const sealed = JSON.parse(seal(JSON.stringify(action), k.serverPublic, k.secret));
    if (sealed.error) throw new DaemonError('crypto', sealed.error);
    const r = await send({ type: 'encrypted', client_id: k.clientId, nonce: sealed.nonce, message: sealed.message });
    if (r.type === 'error') throw new DaemonError(r.code, r.message);
    const opened = JSON.parse(open(r.nonce, r.message, k.serverPublic, k.secret));
    if (opened.error) throw new DaemonError('crypto', opened.error);
    const reply = JSON.parse(opened.plaintext);
    if (reply.result === 'error') throw new DaemonError(reply.code, reply.message);
    return reply;
  }

  async function status(): Promise<Status> {
    const k = await keys();
    try {
      if (!k.serverPublic) {
        await send({ type: 'probe' }).catch(() => {
          throw new Error(t('err_no_host'));
        });
        return { connected: true, associated: false, locked: false };
      }
      const r = await call({ action: 'status' });
      return { connected: true, associated: true, locked: r.locked };
    } catch (e) {
      const code = (e as DaemonError).code;
      if (code === 'locked') return { connected: true, associated: true, locked: true };
      if (code === 'not_associated') return { connected: true, associated: false, locked: false };
      return { connected: false, associated: !!k.serverPublic, locked: false, error: (e as Error).message };
    }
  }

  // popup и другие страницы самого расширения (их адрес chrome-extension:// или moz-extension://)
  const fromExtension = (sender: Browser.runtime.MessageSender) => !!sender.url?.startsWith(browser.runtime.getURL('/'));

  // адрес берём у браузера (sender / вкладка), а не из сообщения страницы
  async function pageUrl(sender: Browser.runtime.MessageSender, tabId?: number): Promise<string> {
    if (!fromExtension(sender) && sender.tab && sender.url) {
      if (sender.frameId !== 0) throw new DaemonError('frame', t('err_frames'));
      return sender.url;
    }
    const tab = tabId !== undefined ? await browser.tabs.get(tabId) : (await browser.tabs.query({ active: true, currentWindow: true }))[0];
    if (!tab?.url) throw new DaemonError('no_tab', t('err_no_tab'));
    return tab.url;
  }

  function tabOf(sender: Browser.runtime.MessageSender, tabId?: number): Promise<number> {
    if (fromExtension(sender) && tabId !== undefined) return Promise.resolve(tabId);
    if (!fromExtension(sender) && sender.tab?.id !== undefined) return Promise.resolve(sender.tab.id);
    return browser.tabs.query({ active: true, currentWindow: true }).then((t) => t[0].id!);
  }

  // последнее заполнение логина во вкладке: на следующем шаге входа того же сайта вставим код 2FA
  const lastFill = new Map<number, { site: string; id: string; at: number }>();
  const hostOf = (url: string) => new URL(url).hostname;

  // последний аккаунт, которым входили на сайт: в меню и popup он первый (хранится только здесь)
  async function rememberUsed(url: string, id: string) {
    const { lastUsed = {} } = (await browser.storage.local.get('lastUsed')) as { lastUsed?: Record<string, string> };
    await browser.storage.local.set({ lastUsed: { ...lastUsed, [hostOf(url)]: id } });
  }
  async function withLastFirst(url: string, logins: Login[]): Promise<Login[]> {
    const { lastUsed = {} } = (await browser.storage.local.get('lastUsed')) as { lastUsed?: Record<string, string> };
    const last = lastUsed[hostOf(url)];
    return [...logins].sort((a, b) => Number(b.id === last) - Number(a.id === last));
  }

  // число аккаунтов сайта на значке расширения (как у Bitwarden); без связи и в блокировке пусто
  async function badge(tabId: number, url?: string) {
    let text = '';
    if (url?.startsWith('http')) {
      try {
        const n = ((await call({ action: 'get_logins', url })).logins as Login[]).length;
        text = n ? String(n) : '';
      } catch {
        text = '';
      }
    }
    await browser.action.setBadgeText({ tabId, text }).catch(() => {});
  }
  browser.action.setBadgeBackgroundColor({ color: '#7c5cff' }).catch(() => {});
  browser.tabs.onActivated.addListener(({ tabId }) => browser.tabs.get(tabId).then((t) => badge(tabId, t.url)).catch(() => {}));
  browser.tabs.onUpdated.addListener((tabId, info, t) => {
    if (info.status === 'complete') badge(tabId, t.url);
  });

  // предложение сохранить пароль переживает переход на следующую страницу
  const pending = new Map<number, PendingSave & { url: string; at: number }>();

  async function handle(msg: Msg, sender: Browser.runtime.MessageSender): Promise<unknown> {
    switch (msg.type) {
      case 'status':
        return status();
      case 'associate':
        return associate();
      case 'classify':
        await ready;
        return JSON.parse(classifyFields(JSON.stringify(msg.fields as FieldInfo[])));
      case 'logins': {
        const url = await pageUrl(sender, msg.tabId);
        const r = await call({ action: 'get_logins', url });
        return withLastFirst(url, r.logins as Login[]);
      }
      case 'fill': {
        const url = await pageUrl(sender, msg.tabId);
        const r = await call({ action: 'fill', id: msg.id, url });
        lastFill.set(await tabOf(sender, msg.tabId), { site: hostOf(url), id: msg.id, at: Date.now() });
        rememberUsed(url, msg.id);
        if (fromExtension(sender)) {
          // из popup: передаём учётку content script вкладки
          await browser.tabs.sendMessage(await tabOf(sender, msg.tabId), { type: 'fillWith', username: r.username, password: r.password }, { frameId: 0 });
          return null;
        }
        return { username: r.username, password: r.password };
      }
      case 'totp': {
        const r = await call({ action: 'totp', id: msg.id, url: await pageUrl(sender, msg.tabId) });
        if (fromExtension(sender)) {
          await browser.tabs.sendMessage(await tabOf(sender, msg.tabId), { type: 'fillOtp', code: r.code }, { frameId: 0 });
          return null;
        }
        return r.code as string;
      }
      case 'generate': {
        // поле нового пароля на сайте: те же настройки, что выбраны в генераторе popup
        const { genOptions } = await browser.storage.local.get('genOptions');
        return (await call({ action: 'generate', options: genOptions ?? null })).password as string;
      }
      case 'generateWith': {
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        await browser.storage.local.set({ genOptions: msg.options });
        const r = await call({ action: 'generate', options: msg.options });
        return { password: r.password as string, entropy: r.entropy as number };
      }
      case 'fillNew':
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        await browser.tabs.sendMessage(await tabOf(sender, msg.tabId), { type: 'fillNew', password: msg.password }, { frameId: 0 });
        return null;
      // поиск по базе, карточка и копирование: только из popup, не со страниц сайтов
      case 'search':
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        return (await call({ action: 'search', query: msg.query, filter: msg.filter ?? null })).logins as Login[];
      case 'lock':
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        await call({ action: 'lock' });
        return null;
      case 'create': {
        // новая запись из popup: адрес и данные ввёл сам пользователь в окне расширения
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        if (!msg.password) throw new DaemonError('invalid', t('err_password_required'));
        const r = await call({ action: 'save', url: msg.url, username: msg.username, password: msg.password, title: msg.title || null, update_id: null });
        return r.id as string;
      }
      case 'facets': {
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        const r = await call({ action: 'facets' });
        return { folders: r.folders, tags: r.tags };
      }
      case 'item':
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        return (await call({ action: 'item', id: msg.id })).item;
      case 'copy':
        if (!fromExtension(sender)) throw new DaemonError('denied', t('err_extension_only'));
        await call({ action: 'copy', id: msg.id, field: msg.field });
        return true;
      case 'autoOtp': {
        // только content script самой вкладки, только тот же сайт, только 3 минуты и один раз
        if (fromExtension(sender) || !(await loadPrefs()).autoOtp) return null;
        const tab = await tabOf(sender);
        const f = lastFill.get(tab);
        const url = await pageUrl(sender);
        if (!f || Date.now() - f.at > 3 * 60_000 || hostOf(url) !== f.site) return null;
        const logins = (await call({ action: 'get_logins', url })).logins as Login[];
        if (!logins.some((l) => l.id === f.id && l.has_otp)) return null;
        lastFill.delete(tab);
        return (await call({ action: 'totp', id: f.id, url })).code as string;
      }
      case 'neverSave': {
        const tab = await tabOf(sender, msg.tabId);
        const p = pending.get(tab);
        pending.delete(tab);
        if (!p) return null;
        const prefs = await loadPrefs();
        if (!prefs.neverSites.includes(p.site)) await savePrefs({ ...prefs, neverSites: [...prefs.neverSites, p.site] });
        return true;
      }
      case 'submitted': {
        if (!msg.password) return null;
        const url = await pageUrl(sender);
        const prefs = await loadPrefs();
        if (!prefs.offerSave || prefs.neverSites.includes(hostOf(url))) return null;
        const r = await call({ action: 'check_save', url, username: msg.username, password: msg.password });
        if (r.state === 'same') return null;
        const site = new URL(url).hostname;
        pending.set(await tabOf(sender), { site, url, username: msg.username, password: msg.password, state: r.state, id: r.id, at: Date.now() });
        return true;
      }
      case 'pendingSave': {
        const tab = await tabOf(sender, msg.tabId);
        const p = pending.get(tab);
        // предложение живёт 5 минут и только на том же сайте
        if (!p || Date.now() - p.at > 5 * 60_000 || new URL(await pageUrl(sender, msg.tabId)).hostname !== p.site) return null;
        // пароль отдаём только той же вкладке того же сайта, где его только что ввели: показать по глазу
        return { site: p.site, username: p.username, password: p.password, state: p.state };
      }
      case 'save': {
        const tab = await tabOf(sender, msg.tabId);
        const p = pending.get(tab);
        pending.delete(tab);
        if (!p || !msg.accept) return null;
        await call({ action: 'save', url: p.url, username: p.username, password: p.password, update_id: p.state === 'changed' ? p.id : null });
        return true;
      }
      case 'passkeyCreate':
        return (await call({ action: 'passkey_create', url: await pageUrl(sender), options: msg.options })).credential;
      case 'passkeyList':
        return (await call({ action: 'passkey_list', url: await pageUrl(sender), options: msg.options })).candidates as Login[];
      case 'passkeyGet':
        return (await call({ action: 'passkey_get', url: await pageUrl(sender), options: msg.options, id: msg.id })).credential;
      case 'openUnlock':
        await send({ type: 'open_unlock' });
        return null;
      default:
        // popup новее фоновой части: Chrome ещё держит старый service worker
        throw new DaemonError('outdated', t('err_outdated'));
    }
  }

  browser.runtime.onMessage.addListener((msg: Msg, sender) => {
    return handle(msg, sender).then(
      (value): Reply<unknown> => ({ ok: true, value }),
      (e): Reply<unknown> => ({ ok: false, code: (e as DaemonError).code ?? 'error', error: (e as Error).message }),
    );
  });

  // значок K: панель на странице; где расширениям нельзя (chrome://, магазин), обычное окно Chrome
  if (import.meta.env.BROWSER !== 'firefox') {
    browser.action.setPopup({ popup: '' }).catch(() => {});
    browser.action.onClicked.addListener(async (tab) => {
      const toggle = () => browser.tabs.sendMessage(tab.id!, { type: 'togglePanel' }, { frameId: 0 });
      try {
        if (tab.id === undefined || !tab.url?.startsWith('http')) throw new Error('служебная страница');
        try {
          await toggle();
        } catch {
          // вкладка открыта до обновления расширения: скрипта страницы на ней нет, подгружаем по клику
          await browser.scripting.executeScript({ target: { tabId: tab.id }, files: ['/content-scripts/content.js'] });
          await toggle();
        }
      } catch {
        await browser.action.setPopup({ popup: 'popup.html' });
        await (browser.action as any).openPopup?.().catch(() => {});
        await browser.action.setPopup({ popup: '' });
      }
    });
  }

  browser.commands.onCommand.addListener(async (command) => {
    if (command !== 'fill-login') return;
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.id !== undefined) browser.tabs.sendMessage(tab.id, { type: 'triggerFill' }, { frameId: 0 }).catch(() => {});
  });
});
