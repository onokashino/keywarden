// Content script: только работа с DOM. Какие поля логин/пароль/2FA, решает Rust (WASM в
// background), выдавать ли пароль этому сайту, решает демон. Поля описываются без значений.
import type { Classified, ContentMsg, DataField, FieldInfo, Login, LoginForm, Msg, Reply } from '../utils/messages';
import { DEFAULT_PREFS, loadPrefs } from '../utils/prefs';
import { t } from '../utils/i18n';
import { applyTheme, cachedTheme, type Theme } from '../utils/theme';

// общий вид всех элементов на странице: нейтральная палитра Keywarden (как в приложении)
const CSS_BASE = `:host{all:initial}
  .card{font:13px/1.45 Inter,system-ui,sans-serif;background:var(--kw-bg, #18181b);color:var(--kw-fg, #ececef);border:1px solid var(--kw-border, #2a2a2f);border-radius:14px;
    box-shadow:0 12px 32px #0009,0 0 0 1px #0004}
  .muted{color:var(--kw-muted, #8e8e98)}
  button{all:unset;box-sizing:border-box;cursor:pointer;font:500 12px Inter,system-ui,sans-serif;padding:6px 12px;border-radius:8px;
    border:1px solid var(--kw-input-border, #2c2d33);color:var(--kw-fg, #ececef);background:var(--kw-surface, #222227);transition:background .12s;white-space:nowrap}
  button:hover{background:var(--kw-surface-hover, #2a2a30)}
  button:focus-visible{outline:2px solid var(--kw-primary, #7c5cff);outline-offset:1px}
  button.primary{background:var(--kw-primary, #7c5cff);border-color:var(--kw-primary, #7c5cff);color:var(--kw-on-primary, #fff)}
  button.primary:hover{background:var(--kw-primary-hover, #8a6dff)}
  button.ghost{background:transparent;border-color:transparent;color:var(--kw-muted, #8e8e98)}
  button.ghost:hover{color:var(--kw-fg, #ececef);background:var(--kw-surface, #222227)}
  @keyframes kw-in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
  .anim{animation:kw-in .16s cubic-bezier(.22,1,.36,1)}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}`;

// тот же знак, что public/icon/logo.svg: в теневом дереве страницы файл расширения не открыть без web_accessible_resources
const LOGO = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#a892ff"/><stop offset="1" stop-color="#6d4aff"/></linearGradient></defs><rect width="64" height="64" rx="15" fill="url(#g)"/><path d="M32 13l15 5.5v11c0 10-6.5 16.5-15 19.5-8.5-3-15-9.5-15-19.5v-11z" fill="none" stroke="#fff" stroke-width="3.6" stroke-linejoin="round"/><circle cx="32" cy="29" r="4.4" fill="#fff"/><path d="M30 31.5h4l1.2 8.5h-6.4z" fill="#fff"/></svg>';

async function ask<T>(msg: Msg): Promise<T> {
  const r = (await browser.runtime.sendMessage(msg)) as Reply<T>;
  if (!r.ok) throw Object.assign(new Error(r.error), { code: r.code });
  return r.value;
}

export default defineContentScript({
  matches: ['https://*/*', 'http://*/*'],
  allFrames: true,
  runAt: 'document_idle',
  main(ctx) {
    // во фрейме работаем, только если он и все рамки над ним с того же адреса, что вкладка:
    // чужой iframe мог бы выманить пароль, а к чужому окну доступа нет (обращение бросает ошибку)
    const framed = window !== window.top;
    try {
      for (let w: Window = window; w !== window.top; w = w.parent) if (w.parent.location.origin !== location.origin) return;
    } catch {
      return;
    }
    let inputs: HTMLInputElement[] = [];
    // поля ввода и за ними списки <select>: индексы полей ввода те же, что в inputs
    let els: (HTMLInputElement | HTMLSelectElement)[] = [];
    let forms: LoginForm[] = [];
    let data: DataField[] = [];
    const decorated = new WeakSet<HTMLInputElement>();
    let prefs = DEFAULT_PREFS;
    // цвета темы приложения: их получает фоновая часть, здесь только читаем
    let theme: Theme | null = null;
    cachedTheme().then((v) => (theme = v));
    let otpDone = false;

    let timer: number | undefined;
    function watch(node: Node) {
      new MutationObserver(() => {
        clearTimeout(timer);
        timer = ctx.setTimeout(scan, 400) as unknown as number;
      }).observe(node, { childList: true, subtree: true });
    }

    // --- страница с веб-компонентами: поля лежат в открытых shadow root, обычный поиск их не видит ---
    const roots = new WeakSet<ShadowRoot>();
    function deep<T extends Element>(sel: string, root: ParentNode = document): T[] {
      const out = [...root.querySelectorAll<T>(sel)];
      for (const h of root.querySelectorAll('*')) {
        const sr = h.shadowRoot;
        if (!sr) continue;
        // изменения внутри shadow root до наблюдателя документа не доходят
        if (!roots.has(sr)) {
          roots.add(sr);
          watch(sr);
        }
        out.push(...deep<T>(sel, sr));
      }
      return out;
    }
    /// поле с фокусом, даже если оно внутри веб-компонента
    function active(): Element | null {
      let a = document.activeElement;
      while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
      return a;
    }
    /// настоящая цель события: снаружи веб-компонента виден только он сам
    const origin = (e: Event) => (e.composedPath()[0] ?? e.target) as EventTarget | null;
    /// contains, который проходит сквозь границы shadow root
    function within(anc: Node, node: Node | null): boolean {
      for (let n = node; n; n = n.parentNode ?? (n as ShadowRoot).host ?? null) if (n === anc) return true;
      return false;
    }
    /// верхний чужой элемент в точке, с заходом внутрь веб-компонентов
    function topAt(x: number, y: number): Element | undefined {
      let n = document.elementsFromPoint(x, y).find((n) => !n.localName.startsWith('keywarden-'));
      while (n?.shadowRoot) {
        const inner = n.shadowRoot.elementsFromPoint(x, y)[0];
        if (!inner || inner === n || !within(n, inner)) break;
        n = inner;
      }
      return n;
    }
    let formList: HTMLFormElement[] = [];

    // --- сбор полей ---
    function visible(el: HTMLElement): boolean {
      const r = el.getBoundingClientRect();
      if (r.width < 8 || r.height < 8) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) < 0.1) return false;
      return (el as any).checkVisibility ? (el as any).checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) : true;
    }

    function labelOf(el: HTMLElement): string {
      const byFor = el.id ? (el.getRootNode() as ParentNode).querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent : '';
      return [byFor, el.closest('label')?.textContent, el.getAttribute('aria-label')].filter(Boolean).join(' ').slice(0, 80);
    }

    async function scan() {
      inputs = deep<HTMLInputElement>('input').filter((i) =>
        ['text', 'email', 'tel', 'number', 'password', ''].includes(i.type),
      );
      els = [...inputs, ...deep<HTMLSelectElement>('select')];
      formList = deep<HTMLFormElement>('form');
      const fields: FieldInfo[] = els.map((el, index) => ({
        index,
        form: el.form ? formList.indexOf(el.form) : -1,
        type: el instanceof HTMLSelectElement ? 'select' : el.type,
        name: el.name,
        id: el.id,
        autocomplete: el.autocomplete ?? '',
        placeholder: el instanceof HTMLInputElement ? (el.placeholder ?? '') : '',
        label: labelOf(el),
        visible: visible(el),
        maxlength: el instanceof HTMLInputElement && el.maxLength > 0 ? el.maxLength : null,
      }));
      if (!fields.some((f) => f.visible)) return;
      const c = await ask<Classified>({ type: 'classify', fields }).catch(() => ({ forms: [], data: [] }) as Classified);
      forms = c.forms;
      data = c.data;
      for (const f of forms) {
        for (const i of [f.username, f.password, ...f.new_passwords, f.otp]) {
          const el = i !== null ? inputs[i] : null;
          if (el) decorate(el, (auto) => openMenu(el, f, auto));
        }
      }
      // карты и личные данные: значок только в уверенно распознанных полях ввода (не в списках)
      for (const d of data) {
        const el = els[d.index];
        if (d.auto && el instanceof HTMLInputElement) decorate(el, (auto) => openDataMenu(el, d, auto));
      }
      fillOnLoad();
      autoOtp();
    }

    // второй шаг входа: поле кода появилось на том же сайте сразу после заполнения логина
    async function autoOtp() {
      if (otpDone || !prefs.autoOtp) return;
      const f = forms.find((x) => x.otp !== null && x.password === null);
      const el = f && inputs[f.otp!];
      if (!el || el.value || !visible(el)) return;
      otpDone = true;
      const code = await ask<string | null>({ type: 'autoOtp' }).catch(() => null);
      if (code && !el.value) {
        setValue(el, code);
        toast(t('toast_otp_inserted'));
        // по желанию: код вставлен, ждать нечего
        if (prefs.otpSubmit) el.form?.requestSubmit();
      }
    }

    // --- значок в поле ---
    function decorate(el: HTMLInputElement, open: (auto: boolean) => void) {
      if (decorated.has(el)) return;
      decorated.add(el);
      el.addEventListener('focus', () => {
        if (!filling && prefs.menuOnFocus && menu?.anchor !== el) open(true);
      });
      el.addEventListener('click', (e) => {
        if (e.isTrusted && !filling && prefs.menuOnFocus && !menu) open(true);
      });
      if (!prefs.icons) return;
      const host = document.createElement('keywarden-icon');
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>
        button{all:unset;cursor:pointer;width:20px;height:20px;border-radius:6px;display:block;opacity:.85;transition:opacity .12s,transform .12s}
        button:hover{opacity:1;transform:scale(1.08)}
        svg{display:block;width:20px;height:20px}</style><button title="Keywarden" aria-label="Keywarden">${LOGO}</button>`;
      Object.assign(host.style, { position: 'absolute', zIndex: '2147483646' });
      document.documentElement.appendChild(host);
      // поле закрыто чужим слоем (окно выбора поверх формы): значок не должен торчать сквозь него
      const covered = () => {
        const r = el.getBoundingClientRect();
        const x = r.right - 18;
        const y = r.top + r.height / 2;
        if (x < 0 || y < 0 || x > window.innerWidth || y > window.innerHeight) return false;
        const top = topAt(x, y);
        if (!top || top === el || within(top, el)) return false;
        // подпись или кнопка рядом с полем лежат в той же обёртке: это не «закрыто»
        let near: Element | null = el;
        for (let i = 0; i < 3 && near; i++) {
          near = near.parentElement;
          // до самой страницы не поднимаемся: в body лежит всё, включая окна поверх
          if (!near || near === document.body || near === document.documentElement) break;
          if (within(near, top)) return false;
        }
        return true;
      };
      // своя кнопка сайта у правого края (глаз «показать пароль», крестик): встаём левее неё
      const free = (r: DOMRect) => {
        let left = r.right - 28;
        const y = r.top + r.height / 2;
        for (let i = 0; i < 3; i++) {
          let hit: Element | undefined;
          for (const dx of [18, 10, 2]) {
            const n = topAt(left + dx, y);
            if (n && n !== el && !within(n, el)) {
              hit = n;
              break;
            }
          }
          if (!hit) break;
          // от попавшейся иконки поднимаемся до всей кнопки
          while (hit.parentElement && !within(hit.parentElement, el)) hit = hit.parentElement;
          const b = hit.getBoundingClientRect();
          const next = b.left - 24;
          // широкий слой (плавающая подпись, окно поверх) не кнопка; дальше середины поля не уходим
          if (!b.width || b.width > r.width / 2 || next < r.left + r.width / 2) break;
          left = next;
        }
        // глаз нарисован фоном поля или псевдоэлементом: его не нащупать, но место под него сайт оставил отступом
        const pad = parseFloat(getComputedStyle(el).paddingRight) || 0;
        if (left === r.right - 28 && pad >= 36 && pad < r.width / 2) left = r.right - pad - 24;
        return left;
      };
      const place = () => {
        const r = el.getBoundingClientRect();
        host.style.display = visible(el) && !covered() ? 'block' : 'none';
        host.style.top = `${r.top + window.scrollY + (r.height - 20) / 2}px`;
        host.style.left = `${free(r) + window.scrollX}px`;
      };
      place();
      ctx.setInterval(place, 500);
      // mousedown, а не click: фокус остаётся в поле, меню не мигает
      root.querySelector('button')!.addEventListener('mousedown', (e) => {
        if (!e.isTrusted) return;
        e.preventDefault();
        if (menu?.anchor === el) return closeMenu();
        el.focus();
        open(false);
      });
    }

    let filling = false;
    // список: вариант, у которого значение или подпись совпали с одним из написаний
    function setSelect(el: HTMLSelectElement, wants: (string | undefined)[]) {
      const norm = (x: string) => x.trim().toLowerCase();
      const w = wants.filter((x): x is string => !!x).map(norm);
      const opt = [...el.options].find((o) => w.includes(norm(o.value)) || w.includes(norm(o.text)));
      if (!opt) return;
      el.value = opt.value;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }

    /// Заполнить поля карты или личных данных той же формы. Срок карты пишется так, как ждёт поле.
    function fillData(d0: DataField, v: Record<string, string>) {
      const mm = v['cc-exp-month'];
      const yyyy = v['cc-exp-year'];
      const yy = yyyy?.slice(-2);
      const alias: Record<string, string> = { 'address-line1': 'street-address', 'country-name': 'country' };
      for (const d of data.filter((x) => x.group === d0.group && x.form === d0.form)) {
        const el = els[d.index];
        if (!el || !visible(el)) continue;
        const role = alias[d.role] ?? d.role;
        if (el instanceof HTMLSelectElement) {
          if (role === 'cc-exp-month') setSelect(el, [mm, mm && String(Number(mm))]);
          else if (role === 'cc-exp-year') setSelect(el, [yyyy, yy]);
          else if (role === 'cc-exp') setSelect(el, mm ? [`${mm}/${yy}`, `${mm}/${yyyy}`] : []);
          else setSelect(el, [v[role]]);
          continue;
        }
        let val: string | undefined = v[role];
        const ph = el.placeholder.toLowerCase();
        if (role === 'cc-exp' && mm && yyyy) {
          const year = /yyyy|гггг/.test(ph) ? yyyy : yy;
          val = el.maxLength === 4 ? `${mm}${yy}` : `${mm}${ph.includes(' / ') ? ' / ' : '/'}${year}`;
        }
        if (role === 'cc-exp-year' && yyyy) val = el.maxLength === 2 || /^(yy|гг)$/.test(ph.trim()) ? yy : yyyy;
        if (val) setValue(el, val);
      }
    }

    function setValue(el: HTMLInputElement, value: string) {
      // нативный setter: React и другие фреймворки иначе не заметят значение
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
      filling = true;
      el.focus();
      setter.call(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      filling = false;
    }

    // двухшаговый вход: если пароля на странице нет, заполняется только логин
    function fill(form: LoginForm, username: string, password: string) {
      if (form.username !== null && username) setValue(inputs[form.username], username);
      if (form.password !== null) setValue(inputs[form.password], password);
    }

    /// Остальные пустые видимые поля той же формы: подпись (имя, id, текст рядом) → поле.
    function extraInputs(form: LoginForm): Map<string, HTMLInputElement> {
      const out = new Map<string, HTMLInputElement>();
      const taken = [form.username, form.password, form.otp, ...form.new_passwords];
      const anchor = inputs[taken.find((i) => i !== null) ?? -1]?.form;
      // без <form> непонятно, какие поля относятся ко входу
      if (!anchor) return out;
      inputs.forEach((el, i) => {
        if (taken.includes(i) || el.form !== anchor || el.type === 'password' || el.value || !visible(el)) return;
        for (const name of [el.name, el.id, labelOf(el), el.placeholder]) {
          const key = name?.trim().slice(0, 80);
          if (key && !out.has(key)) out.set(key, el);
        }
      });
      return out;
    }

    function formFor(el?: HTMLInputElement): LoginForm | undefined {
      if (el) return forms.find((f) => [f.username, f.password, f.otp, ...f.new_passwords].some((i) => i !== null && inputs[i] === el));
      return forms.find((f) => f.password !== null) ?? forms.find((f) => f.username !== null) ?? forms[0];
    }

    function failed(e: unknown) {
      const code = (e as any).code;
      if (code === 'locked') {
        toast(t('toast_vault_locked_open'));
        ask({ type: 'openUnlock' }).catch(() => {});
      } else toast((e as Error).message);
    }

    async function fillWith(form: LoginForm, l: Login) {
      try {
        const others = extraInputs(form);
        const c = await ask<{ username: string; password: string; extra?: [string, string][] }>({ type: 'fill', id: l.id, extra: [...others.keys()] });
        fill(form, c.username, c.password);
        // свои поля записи (фамилия, номер договора) в поля формы с тем же названием
        for (const [name, value] of c.extra ?? []) {
            const el = others.get(name);
            if (el && !el.value) setValue(el, value);
        }
        // код 2FA этой записи сразу в буфер: на следующем шаге его остаётся вставить
        if (l.has_otp && prefs.otpClipboard) {
          ask<boolean>({ type: 'copyOtp', id: l.id })
            .then((ok) => ok && toast(t('toast_otp_copied')))
            .catch(() => {});
        }
      } catch (e) {
        failed(e);
      }
    }

    // заполнение при открытии страницы: только защищённая страница, пустая форма, ровно одна запись
    // сайта и сайт уже разрешён для неё в Keywarden (иначе демон откажет без вопроса)
    let loadFilled = false;
    async function fillOnLoad() {
      if (loadFilled || !prefs.fillOnLoad) return;
      const f = forms.find((x) => x.password !== null);
      const secure = location.protocol === 'https:' || /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(location.hostname);
      if (!f || !secure) return;
      loadFilled = true;
      const pw = inputs[f.password!];
      if (pw.value || (f.username !== null && inputs[f.username].value)) return;
      const logins = await siteLogins().catch(() => [] as Login[]);
      if (logins.length !== 1) return;
      const c = await ask<{ username: string; password: string }>({ type: 'fill', id: logins[0].id, quiet: true }).catch(() => null);
      if (c && !pw.value) fill(f, c.username, c.password);
    }

    // поле, по которому щёлкнули правой кнопкой: меню браузера сообщает только вкладку
    let ctxTarget: EventTarget | null = null;
    document.addEventListener('contextmenu', (e) => (ctxTarget = origin(e)), true);

    /// Поле не распознано как вход: берём его само и ближайшее парное (логин перед паролем или пароль после логина).
    function adhocForm(el: HTMLInputElement): LoginForm | undefined {
      const idx = inputs.indexOf(el);
      if (idx < 0) return undefined;
      const near = (from: number, step: number, password: boolean) => {
        for (let i = from; i >= 0 && i < inputs.length; i += step) {
          if ((inputs[i].type === 'password') === password && visible(inputs[i])) return i;
        }
        return null;
      };
      return el.type === 'password'
        ? { form: -2, username: near(idx - 1, -1, false), password: idx, new_passwords: [], otp: null }
        : { form: -2, username: idx, password: near(idx + 1, 1, true), new_passwords: [], otp: null };
    }

    async function onContext(msg: Extract<ContentMsg, { type: 'ctx' }>) {
      await scan();
      const el = ctxTarget instanceof HTMLInputElement && inputs.includes(ctxTarget) ? ctxTarget : null;
      if (msg.action === 'fill') {
        let f = el ? (formFor(el) ?? adhocForm(el)) : formFor();
        // явная просьба «заполнить вход»: поле «новый пароль» тут считаем обычным
        if (el && f?.new_passwords.includes(inputs.indexOf(el))) f = adhocForm(el);
        const anchor = el ?? (f && inputs[f.password ?? f.username ?? f.otp ?? -1]);
        if (!f || !anchor) return toast(t('toast_no_login_field'));
        return quickFill(anchor, f);
      }
      if (msg.action === 'generate') {
        const own = el && formFor(el);
        const targets = el
          ? own?.new_passwords.includes(inputs.indexOf(el))
            ? own.new_passwords.map((i) => inputs[i])
            : [el]
          : (forms.find((x) => x.new_passwords.length)?.new_passwords.map((i) => inputs[i]) ?? []);
        if (!targets.length) return toast(t('toast_no_new_password_field'));
        targets.forEach((x) => setValue(x, msg.password));
        generated = msg.password;
        return toast(t('toast_password_inserted'));
      }
      const group = msg.action;
      const d = data.find((x) => x.group === group && els[x.index] === ctxTarget) ?? data.find((x) => x.group === group && visible(els[x.index]));
      if (!d) return toast(t(group === 'card' ? 'toast_no_card_fields' : 'toast_no_identity_fields'));
      els[d.index].focus();
      openDataMenu(els[d.index], d, false);
    }

    // сгенерированный пароль, вставленный в поле: если страница уйдёт без замеченной отправки формы,
    // всё равно предложим его сохранить
    let generated = '';
    window.addEventListener('pagehide', () => {
      const el = generated ? inputs.find((i) => i.value === generated) : undefined;
      const f = el && (formFor(el) ?? adhocForm(el));
      if (!el || !f) return;
      const username = f.username !== null ? inputs[f.username].value : '';
      ask({ type: 'submitted', username, password: generated }).catch(() => {});
    });

    // --- меню под полем: аккаунты сайта, коды 2FA, новый пароль ---
    type MenuItem = { label: string; sub?: string; avatar?: string; mono?: boolean; pick: () => void };
    let menu: { host: HTMLElement; anchor: HTMLElement; close: () => void; key: (e: KeyboardEvent) => boolean } | null = null;
    // список учёток сайта: одно обращение к Keywarden на несколько фокусов подряд
    let cache: { at: number; logins: Login[] } | null = null;

    function closeMenu() {
      menu?.close();
      menu = null;
    }

    function showMenu(anchor: HTMLElement, title: string, items: MenuItem[], empty?: string) {
      closeMenu();
      const host = document.createElement('keywarden-menu');
      applyTheme(host, theme);
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .m{padding:6px;max-height:320px;overflow:auto;border-radius:14px}
        .t{display:flex;align-items:center;gap:7px;font:600 11px Inter,system-ui,sans-serif;color:var(--kw-muted, #8e8e98);padding:4px 8px 7px}
        .t i{flex:none;width:16px;height:16px}
        .t i svg{display:block;width:16px;height:16px}
        .it{display:flex;align-items:center;gap:10px;width:100%;padding:7px 8px;border:0;border-radius:9px;background:transparent;text-align:left}
        .it{transition:background .1s}
        .it.sel,.it:hover{background:var(--kw-active, #26272d)}
        .it:active{transform:scale(.985)}
        .av{flex:none;width:28px;height:28px;border-radius:8px;background:var(--kw-surface, #222227);border:1px solid var(--kw-input-border, #2c2d33);display:grid;place-items:center;
          font:600 12px Inter,system-ui,sans-serif;color:var(--kw-fg-soft, #c9c9d1)}
        .tx{min-width:0;flex:1}
        .tx b,.tx small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .tx b{font-weight:500;color:var(--kw-fg, #ececef)}
        .tx small{color:var(--kw-muted, #8e8e98);font-size:11px;font-weight:400}
        .mono b{font-family:'JetBrains Mono',ui-monospace,monospace;letter-spacing:.5px}
        .e{padding:6px 8px 8px;color:var(--kw-muted, #8e8e98);font-size:12px}</style>
        <div class="m card anim"><div class="t"><i>${LOGO}</i><span></span></div><div class="l"></div></div>`;
      root.querySelector('.t span')!.textContent = title;
      const list = root.querySelector('.l')!;
      const buttons: HTMLButtonElement[] = [];
      for (const it of items) {
        const b = document.createElement('button');
        b.className = 'it' + (it.mono ? ' mono' : '');
        b.tabIndex = -1;
        const av = document.createElement('span');
        av.className = 'av';
        av.textContent = it.avatar ?? (it.label || '?').trim().slice(0, 1).toUpperCase();
        const tx = document.createElement('span');
        tx.className = 'tx';
        const strong = document.createElement('b');
        strong.textContent = it.label;
        tx.appendChild(strong);
        if (it.sub) {
          const small = document.createElement('small');
          small.textContent = it.sub;
          tx.appendChild(small);
        }
        b.append(av, tx);
        b.addEventListener('click', (e) => {
          if (!e.isTrusted) return;
          closeMenu();
          it.pick();
        });
        list.appendChild(b);
        buttons.push(b);
      }
      if (!items.length && empty) {
        const p = document.createElement('div');
        p.className = 'e';
        p.textContent = empty;
        list.appendChild(p);
      }
      // клики по меню не забирают фокус у поля
      host.addEventListener('mousedown', (e) => e.preventDefault());
      Object.assign(host.style, { position: 'absolute', zIndex: '2147483647' });
      const card = root.querySelector('.m') as HTMLElement;
      const place = () => {
        const w0 = 320;
        if (anchor === document.body) {
          // ключ доступа: поля нет, меню сверху по центру
          card.style.width = `${w0}px`;
          host.style.top = `${72 + window.scrollY}px`;
          host.style.left = `${(window.innerWidth - w0) / 2 + window.scrollX}px`;
          return;
        }
        const r = anchor.getBoundingClientRect();
        const w = Math.min(Math.max(r.width, 280), 380);
        card.style.width = `${w}px`;
        const below = window.innerHeight - r.bottom;
        const h = card.offsetHeight || 200;
        const top = below < h + 12 && r.top > h + 12 ? r.top - h - 6 : r.bottom + 6;
        host.style.top = `${top + window.scrollY}px`;
        host.style.left = `${Math.min(r.left, window.innerWidth - w - 8) + window.scrollX}px`;
      };
      document.documentElement.appendChild(host);
      place();
      let sel = -1;
      const select = (i: number) => {
        buttons[sel]?.classList.remove('sel');
        sel = (i + buttons.length) % buttons.length;
        buttons[sel]?.classList.add('sel');
        buttons[sel]?.scrollIntoView({ block: 'nearest' });
      };
      const onDown = (e: MouseEvent) => {
        if (!e.composedPath().includes(host) && origin(e) !== anchor) closeMenu();
      };
      const onBlur = () => setTimeout(() => menu?.anchor === anchor && active() !== anchor && closeMenu(), 120);
      // пользователь печатает сам: меню не мешает и не закрывает кнопку «Войти»
      const onInput = (e: Event) => e.isTrusted && !filling && closeMenu();
      document.addEventListener('mousedown', onDown, true);
      anchor.addEventListener('input', onInput);
      window.addEventListener('resize', place);
      window.addEventListener('scroll', place, true);
      anchor.addEventListener('blur', onBlur);
      menu = {
        host,
        anchor,
        close: () => {
          host.remove();
          document.removeEventListener('mousedown', onDown, true);
          anchor.removeEventListener('input', onInput);
          window.removeEventListener('resize', place);
          window.removeEventListener('scroll', place, true);
          anchor.removeEventListener('blur', onBlur);
        },
        // стрелки выбирают пункт, Enter заполняет выбранный, Esc закрывает
        key: (e) => {
          if (e.key === 'Escape') return closeMenu(), true;
          if (!buttons.length) return false;
          if (e.key === 'ArrowDown') return select(sel + 1), true;
          if (e.key === 'ArrowUp') return select(sel - 1), true;
          if (e.key === 'Enter' && sel >= 0) {
            const it = items[sel];
            closeMenu();
            it.pick();
            return true;
          }
          return false;
        },
      };
    }

    document.addEventListener(
      'keydown',
      (e) => {
        if (e.isTrusted && menu && active() === menu.anchor && menu.key(e)) {
          e.preventDefault();
          e.stopPropagation();
        }
      },
      true,
    );

    async function siteLogins(): Promise<Login[]> {
      if (cache && Date.now() - cache.at < 15_000) return cache.logins;
      const logins = await ask<Login[]>({ type: 'logins' });
      cache = { at: Date.now(), logins };
      return logins;
    }

    /// `auto`: меню открылось само при фокусе; тогда без записей для сайта и без связи молчим
    async function openMenu(el: HTMLInputElement, form: LoginForm, auto: boolean) {
      const idx = inputs.indexOf(el);
      const host = location.hostname;
      try {
        if (form.new_passwords.includes(idx)) {
          const pw = await ask<string>({ type: 'generate' });
          if (active() !== el && auto) return;
          return showMenu(el, t('menu_new_password', host), [
            {
              label: pw,
              sub: t('menu_generate_sub'),
              avatar: '✱',
              mono: true,
              pick: () => {
                for (const i of form.new_passwords) setValue(inputs[i], pw);
                generated = pw;
                toast(t('toast_password_inserted'));
              },
            },
          ]);
        }
        const logins = await siteLogins();
        if (active() !== el && auto) return;
        if (form.otp === idx) {
          const withOtp = logins.filter((l) => l.has_otp);
          if (!withOtp.length && auto) return;
          return showMenu(
            el,
            t('menu_otp_title', host),
            withOtp.map((l) => ({
              label: l.title,
              sub: l.username ? t('menu_otp_sub_for', l.username) : t('menu_otp_sub'),
              pick: () => ask<string>({ type: 'totp', id: l.id }).then((c) => setValue(el, c), failed),
            })),
            t('menu_no_otp'),
          );
        }
        if (!logins.length && auto) return;
        showMenu(
          el,
          t(logins.length > 1 ? 'menu_choose_account' : 'menu_sign_in', host),
          logins.map((l) => ({ label: l.username || l.title, sub: l.username ? l.title : l.group, pick: () => fillWith(form, l) })),
          t('menu_no_logins'),
        );
      } catch (e) {
        if ((e as any).code === 'locked') lockedMenu(el);
        else if (!auto) failed(e);
      }
    }

    function lockedMenu(el: HTMLElement) {
      showMenu(el, `Keywarden · ${location.hostname}`, [
        {
          label: t('unlock_keywarden'),
          sub: t('vault_locked'),
          avatar: '🔒',
          pick: () => {
            cache = null;
            ask({ type: 'openUnlock' }).catch(() => {});
          },
        },
      ]);
    }

    /// Меню карт или личных данных под полем. По явной просьбе единственная запись заполняется сразу.
    async function openDataMenu(el: HTMLElement, d: DataField, auto: boolean) {
      const card = d.group === 'card';
      const use = (l: Login) => ask<Record<string, string>>({ type: 'dataFill', id: l.id }).then((v) => fillData(d, v), failed);
      try {
        const list = await ask<Login[]>({ type: 'dataList', kind: d.group });
        if (auto && (active() !== el || !list.length)) return;
        if (!auto && list.length === 1) return void use(list[0]);
        showMenu(
          el,
          t(card ? 'menu_cards' : 'menu_identities'),
          list.map((l) => ({ label: l.title, sub: l.username, pick: () => use(l) })),
          t(card ? 'menu_no_cards' : 'menu_no_identities'),
        );
      } catch (e) {
        if ((e as any).code === 'locked') lockedMenu(el);
        else if (!auto) failed(e);
      }
    }

    // горячая клавиша: один аккаунт заполняется сразу, несколько открывают меню
    async function quickFill(el: HTMLInputElement, form: LoginForm) {
      const idx = inputs.indexOf(el);
      if (form.new_passwords.includes(idx) || form.otp === idx) return openMenu(el, form, false);
      try {
        const logins = await siteLogins();
        if (logins.length === 1) return fillWith(form, logins[0]);
      } catch (e) {
        return failed(e);
      }
      el.focus();
      openMenu(el, form, false);
    }

    // --- выбор из списка по центру страницы (ключи доступа, аккаунт для копирования) ---
    type Row<T> = { label: string; sub?: string; avatar?: string; value: T };
    function chooseRow<T>(anchor: HTMLElement, title: string, rows: Row<T>[]): Promise<T | null> {
      return new Promise((resolve) => {
        let done = false;
        showMenu(
          anchor,
          title,
          rows.map((r) => ({ label: r.label, sub: r.sub, avatar: r.avatar, pick: () => ((done = true), resolve(r.value)) })),
        );
        const m = menu!;
        const close = m.close;
        // меню сначала закрывается и только потом сообщает выбор: отказ считаем после этого
        m.close = () => {
          close();
          setTimeout(() => !done && resolve(null), 0);
        };
      });
    }
    function choose(anchor: HTMLElement, logins: Login[], title: string): Promise<Login | null> {
      if (logins.length === 0) {
        toast(t('toast_no_entries'));
        return Promise.resolve(null);
      }
      return chooseRow(anchor, title, logins.map((l) => ({ label: l.title, sub: l.username || l.group, value: l })));
    }

    /// Сайт просит ключ доступа, а база закрыта: разблокировать и продолжить в Keywarden
    /// или уйти в обычный вход браузера (устройство, аппаратный ключ). true: база открыта.
    async function unlockForPasskey(): Promise<boolean> {
      const pick = await chooseRow(document.body, t('passkey_locked_title'), [
        { label: t('unlock_keywarden'), sub: t('passkey_unlock_sub'), avatar: '🔒', value: 'unlock' as const },
        { label: t('passkey_use_device'), sub: t('passkey_use_device_sub'), avatar: '⌁', value: 'device' as const },
      ]);
      if (pick !== 'unlock') return false;
      ask({ type: 'openUnlock' }).catch(() => {});
      for (let i = 0; i < 120; i++) {
        await new Promise<void>((r) => ctx.setTimeout(() => r(), 1000));
        const st = await ask<{ locked: boolean; connected: boolean }>({ type: 'status' }).catch(() => null);
        if (st?.connected && !st.locked) return true;
      }
      return false;
    }

    function toast(text: string) {
      const host = document.createElement('keywarden-toast');
      applyTheme(host, theme);
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .card{position:fixed;top:16px;right:16px;z-index:2147483647;padding:10px 14px;max-width:360px;display:flex;gap:8px;align-items:center}
        i{flex:none;width:20px;height:20px}
        i svg{display:block;width:20px;height:20px}</style><div class="card anim"><i>${LOGO}</i><span></span></div>`;
      root.querySelector('span')!.textContent = text;
      document.documentElement.appendChild(host);
      ctx.setTimeout(() => host.remove(), 4000);
    }

    // --- предложение сохранить пароль ---
    function captureSubmit(form?: LoginForm) {
      const f = form ?? formFor();
      if (!f) return;
      const pwIdx = f.password ?? f.new_passwords[0] ?? null;
      const password = pwIdx !== null ? inputs[pwIdx]?.value : '';
      const username = f.username !== null ? inputs[f.username].value : '';
      if (!password) {
        // вход в два шага: логин уходит первой страницей, запоминаем его к паролю со следующей
        if (username) ask({ type: 'submitted', username, password: '' }).catch(() => {});
        return;
      }
      ask({ type: 'submitted', username, password })
        .then((r) => {
          if (!r) return;
          // форму отправили повторно (сайт отклонил первый пароль): окно с прежними данными заменяем
          document.querySelector('keywarden-save')?.remove();
          // окно сохранения рисует сама вкладка: во фрейме ему может не хватить места
          if (!framed) showSave();
        })
        .catch(() => {});
    }

    async function showSave() {
      const p = await ask<{ site: string; username: string; password: string; state: string } | null>({ type: 'pendingSave' }).catch(() => null);
      if (!p || document.querySelector('keywarden-save')) return;
      const host = document.createElement('keywarden-save');
      applyTheme(host, theme);
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .b{position:fixed;top:16px;right:16px;z-index:2147483647;width:340px;overflow:hidden}
        .h{display:flex;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--kw-line, #26262b)}
        .logo{flex:none;width:28px;height:28px}
        .logo svg{display:block;width:28px;height:28px}
        .title{font-weight:600}
        .site{font-size:12px}
        .who{padding:10px 14px;display:flex;justify-content:space-between;align-items:center;gap:8px;min-height:40px;box-sizing:border-box}
        .who + .who{border-top:1px solid var(--kw-border, #25252a)}
        .who b{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .pw{display:flex;align-items:center;gap:6px;min-width:0}
        .pw b{font-family:'JetBrains Mono',ui-monospace,monospace;letter-spacing:.5px}
        .pw b.dots{letter-spacing:2px;color:var(--kw-fg-soft, #c9c9d1)}
        .eye{padding:4px;display:grid;place-items:center;border-radius:6px}
        .eye svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
        .r{display:flex;gap:6px;align-items:center;padding:10px 14px;border-top:1px solid var(--kw-line, #26262b);background:var(--kw-sunken, #141417)}
        .uin{all:unset;box-sizing:border-box;min-width:0;flex:1;text-align:right;font:500 13px Inter,system-ui,sans-serif;color:var(--kw-fg, #ececef);
          height:20px;line-height:18px;padding:0 8px;border-radius:6px;border:1px solid transparent}
        .uin:hover{border-color:var(--kw-input-border, #2c2d33)}
        .uin:focus{border-color:var(--kw-primary, #7c5cff);background:var(--kw-sunken, #141417)}
        .sp{flex:1}</style>
        <div class="b card anim">
          <div class="h"><div class="logo">${LOGO}</div><div><div class="title"></div><div class="site muted"></div></div></div>
          <div class="who"><span class="muted">${t('username')}</span><b class="user"></b></div>
          <div class="who"><span class="muted">${t('password')}</span>
            <span class="pw"><b class="dots"></b><button class="ghost eye"></button></span></div>
          <div class="r"><button class="ghost never">${t('never_here')}</button><span class="sp"></span>
            <button class="n">${t('not_now')}</button><button class="p primary"></button></div>
        </div>`;
      if (p.state === 'locked') {
        // сохранять некуда, пока база закрыта: одна кнопка, после разблокировки показываем обычное предложение
        root.querySelectorAll('.who,.never').forEach((el) => el.remove());
        root.querySelector('.title')!.textContent = t('prompt_unlock_to_save');
        root.querySelector('.site')!.textContent = p.site;
        const btn = root.querySelector('.p') as HTMLButtonElement;
        btn.textContent = t('unlock');
        let timer = 0;
        const close = () => {
          clearInterval(timer);
          host.remove();
        };
        btn.addEventListener('click', (e) => {
          if (!e.isTrusted) return;
          ask({ type: 'openUnlock' }).catch((err) => toast((err as Error).message));
          clearInterval(timer);
          let left = 120;
          timer = window.setInterval(async () => {
            const st = await ask<{ locked: boolean }>({ type: 'status' }).catch(() => null);
            if (st && !st.locked) {
              close();
              showSave();
            } else if (--left <= 0) clearInterval(timer);
          }, 1000);
        });
        root.querySelector('.n')!.addEventListener('click', (e) => {
          if (!e.isTrusted) return;
          close();
          ask({ type: 'save', accept: false }).catch(() => {});
        });
        document.documentElement.appendChild(host);
        return;
      }
      const changed = p.state === 'changed';
      root.querySelector('.title')!.textContent = t(changed ? 'prompt_update_keywarden' : 'prompt_save_keywarden');
      root.querySelector('.site')!.textContent = p.site;
      const userEl = root.querySelector('.who b.user') as HTMLElement;
      userEl.textContent = p.username || t('no_username');
      // у новой записи логин можно поправить до сохранения (сайт мог назвать поле по-своему)
      let userIn: HTMLInputElement | null = null;
      if (!changed) {
        userIn = document.createElement('input');
        userIn.className = 'uin';
        userIn.value = p.username;
        userIn.placeholder = t('no_username');
        userIn.setAttribute('aria-label', t('username'));
        // горячие клавиши страницы не должны срабатывать, пока печатают логин
        for (const ev of ['keydown', 'keyup', 'keypress']) userIn.addEventListener(ev, (e) => e.stopPropagation());
        userEl.replaceWith(userIn);
      }
      // пароль скрыт точками, глаз показывает и прячет (как в приложении)
      const pwEl = root.querySelector('.pw b') as HTMLElement;
      const eye = root.querySelector('.eye') as HTMLButtonElement;
      const eyeOpen = '<svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
      const eyeShut = '<svg viewBox="0 0 24 24"><path d="M3 3l18 18M10.6 10.6a3 3 0 0 0 4.2 4.2M9.9 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/></svg>';
      let shown = false;
      const renderPw = () => {
        pwEl.textContent = shown ? p.password : '•'.repeat(Math.min(Math.max(p.password.length, 8), 14));
        pwEl.classList.toggle('dots', !shown);
        eye.innerHTML = shown ? eyeShut : eyeOpen;
        eye.title = t(shown ? 'hide_password' : 'show_password');
      };
      renderPw();
      eye.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        shown = !shown;
        renderPw();
      });
      root.querySelector('.p')!.textContent = t(changed ? 'update' : 'save');
      const done = (accept: boolean) => (e: Event) => {
        if (!e.isTrusted) return;
        host.remove();
        ask({ type: 'save', accept, username: userIn?.value }).then(() => accept && toast(t('toast_saved_keywarden'))).catch((err) => toast((err as Error).message));
      };
      root.querySelector('.p')!.addEventListener('click', done(true));
      root.querySelector('.n')!.addEventListener('click', done(false));
      root.querySelector('.never')!.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        host.remove();
        ask({ type: 'neverSave' }).then(() => toast(t('toast_never_site', p.site))).catch(() => {});
      });
      document.documentElement.appendChild(host);
    }

    document.addEventListener('submit', (e) => {
      const idx = formList.indexOf(origin(e) as HTMLFormElement);
      captureSubmit(forms.find((f) => f.form === idx));
    }, true);
    // SPA без <form>: Enter в поле пароля или клик по кнопке рядом
    document.addEventListener('keydown', (e) => {
      const el = origin(e);
      if (e.key === 'Enter' && el instanceof HTMLInputElement && formFor(el)) captureSubmit(formFor(el));
    }, true);
    document.addEventListener('click', (e) => {
      const b = (origin(e) as Element)?.closest?.('button,[type=submit],[role=button]');
      if (b && forms.length) captureSubmit();
    }, true);

    // --- окно Keywarden на странице: скруглённая панель с popup.html внутри iframe ---
    let panel: { host: HTMLElement; frame: HTMLIFrameElement; close: () => void } | null = null;
    function togglePanel() {
      if (panel) return panel.close();
      closeMenu();
      const host = document.createElement('keywarden-panel');
      applyTheme(host, theme);
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>
        .p{position:fixed;top:10px;right:12px;z-index:2147483647;width:460px;max-width:calc(100vw - 24px);height:640px;max-height:calc(100vh - 20px);
          border-radius:16px;overflow:hidden;background:var(--kw-sunken, #141417);border:1px solid var(--kw-border, #2a2a2f);
          box-shadow:0 24px 64px #000a,0 0 0 1px #0006;animation:kw-p .18s cubic-bezier(.22,1,.36,1);transform-origin:top right}
        .p.out{animation:kw-out .12s ease-in forwards}
        iframe{border:0;width:100%;height:100%;display:block;color-scheme:dark}
        @keyframes kw-p{from{opacity:0;transform:translateY(-6px) scale(.98)}to{opacity:1;transform:none}}
        @keyframes kw-out{to{opacity:0;transform:translateY(-4px) scale(.98)}}</style><div class="p"></div>`;
      const frame = document.createElement('iframe');
      frame.src = browser.runtime.getURL('/popup.html') + '#panel';
      frame.allow = 'clipboard-write';
      root.querySelector('.p')!.appendChild(frame);
      document.documentElement.appendChild(host);
      const onDown = (e: MouseEvent) => !e.composedPath().includes(host) && close();
      const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close();
      const onMsg = (e: MessageEvent) => {
        if (e.source === frame.contentWindow && e.data?.kw === 'close-panel') close();
      };
      function close() {
        if (!panel) return;
        panel = null;
        document.removeEventListener('mousedown', onDown, true);
        document.removeEventListener('keydown', onKey, true);
        window.removeEventListener('message', onMsg);
        const p = root.querySelector('.p')!;
        p.classList.add('out');
        setTimeout(() => host.remove(), 130);
      }
      document.addEventListener('mousedown', onDown, true);
      document.addEventListener('keydown', onKey, true);
      window.addEventListener('message', onMsg);
      panel = { host, frame, close };
    }

    // --- сообщения от background (горячая клавиша, popup) ---
    browser.runtime.onMessage.addListener((msg: ContentMsg) => {
      if (msg.type === 'ctx') return void onContext(msg);
      if (msg.type === 'notify') return void toast(msg.text);
      // ответ уходит в background: какой аккаунт скопировать
      if (msg.type === 'choose') return choose(document.body, msg.logins, msg.title).then((l) => l?.id ?? null);
      const act = active();
      const focused = act instanceof HTMLInputElement ? act : undefined;
      const f = formFor(focused);
      if (msg.type === 'triggerFill' && f) {
        const el = inputs[f.otp ?? f.password ?? f.username ?? f.new_passwords[0]];
        if (el) quickFill(el, f);
      }
      if (msg.type === 'fillWith' && f) fill(f, msg.username, msg.password);
      if (msg.type === 'togglePanel') togglePanel();
      if (msg.type === 'showSave') showSave();
      if (msg.type === 'fillNew') {
        // поля нового пароля формы, иначе поле пароля в фокусе
        const nf = forms.find((x) => x.new_passwords.length);
        const targets = nf
          ? nf.new_passwords.map((i) => inputs[i])
          : focused?.type === 'password'
            ? [focused]
            : [];
        targets.forEach((el) => setValue(el, msg.password));
        if (!targets.length) toast(t('toast_no_new_password_field'));
      }
      if (msg.type === 'fillOtp') {
        const o = forms.find((x) => x.otp !== null);
        if (o) setValue(inputs[o.otp!], msg.code);
      }
    });

    // --- ключи доступа: запросы из мира страницы (passkeys.content.ts) ---
    // отказ пользователя, нет Keywarden или неподдерживаемый алгоритм → обычный WebAuthn браузера
    const fallbackCodes = ['locked', 'not_associated', 'crypto', 'error'];
    const isFallback = (e: any) =>
      fallbackCodes.includes(e.code) || /NotAllowedError|SecurityError|NotSupportedError|keywarden-host|Specified native/.test(e.message ?? '');
    const reply = (id: string, data: Record<string, unknown>) => window.postMessage({ kw: 'passkey-result', id, ...data }, location.origin);
    window.addEventListener('message', async (e) => {
      if (e.source !== window || e.data?.kw !== 'passkey-request') return;
      const { id, kind, options } = e.data;
      const DEVICE = Symbol('device');
      const run = async () => {
        if (kind === 'create') {
          return reply(id, { ok: true, credential: await ask({ type: 'passkeyCreate', options }) });
        }
        const candidates = await ask<Login[]>({ type: 'passkeyList', options });
        if (candidates.length === 0) return reply(id, { fallback: true });
        // один ключ: Keywarden сразу спросит в своём окне; несколько: выбор и выход в обычный вход браузера
        const pick =
          candidates.length === 1
            ? candidates[0]
            : await chooseRow<Login | typeof DEVICE>(document.body, t('passkey_choose_title'), [
                ...candidates.map((l) => ({ label: l.title, sub: l.username || l.group, value: l })),
                { label: t('passkey_use_device'), sub: t('passkey_use_device_sub'), avatar: '⌁', value: DEVICE },
              ]);
        if (!pick || pick === DEVICE) return reply(id, { fallback: true });
        reply(id, { ok: true, credential: await ask({ type: 'passkeyGet', options, id: pick.id }) });
      };
      try {
        try {
          await run();
        } catch (err) {
          // база закрыта: предлагаем открыть и продолжаем тот же запрос сайта
          if ((err as { code?: string }).code !== 'locked' || !(await unlockForPasskey())) throw err;
          await run();
        }
      } catch (err) {
        const er = err as Error & { code?: string };
        if (isFallback(er)) return reply(id, { fallback: true });
        reply(id, { ok: false, error: er.message, name: er.message.startsWith('InvalidStateError') ? 'InvalidStateError' : 'NotAllowedError' });
      }
    });

    loadPrefs()
      .then((p) => (prefs = p))
      .finally(() =>
        scan().then(() => {
          if (!framed) showSave();
        }),
      );
    browser.storage.onChanged.addListener((c) => {
      if (c.prefs) loadPrefs().then((p) => (prefs = p));
      if (c.theme) theme = (c.theme.newValue as Theme | undefined) ?? null;
    });
    watch(document.documentElement);
  },
});
