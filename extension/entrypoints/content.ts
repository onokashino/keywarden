// Content script: только работа с DOM. Какие поля логин/пароль/2FA, решает Rust (WASM в
// background), выдавать ли пароль этому сайту, решает демон. Поля описываются без значений.
import type { ContentMsg, FieldInfo, Login, LoginForm, Msg, Reply } from '../utils/messages';
import { DEFAULT_PREFS, loadPrefs } from '../utils/prefs';
import { t } from '../utils/i18n';

// общий вид всех элементов на странице: нейтральная палитра Keywarden (как в приложении)
const CSS_BASE = `:host{all:initial}
  .card{font:13px/1.45 Inter,system-ui,sans-serif;background:#18181b;color:#ececef;border:1px solid #2a2a2f;border-radius:14px;
    box-shadow:0 12px 32px #0009,0 0 0 1px #0004}
  .muted{color:#8e8e98}
  button{all:unset;box-sizing:border-box;cursor:pointer;font:500 12px Inter,system-ui,sans-serif;padding:6px 12px;border-radius:8px;
    border:1px solid #2c2d33;color:#ececef;background:#222227;transition:background .12s;white-space:nowrap}
  button:hover{background:#2a2a30}
  button:focus-visible{outline:2px solid #7c5cff;outline-offset:1px}
  button.primary{background:#7c5cff;border-color:#7c5cff;color:#fff}
  button.primary:hover{background:#8a6dff}
  button.ghost{background:transparent;border-color:transparent;color:#8e8e98}
  button.ghost:hover{color:#ececef;background:#222227}
  @keyframes kw-in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
  .anim{animation:kw-in .16s cubic-bezier(.22,1,.36,1)}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}`;

async function ask<T>(msg: Msg): Promise<T> {
  const r = (await browser.runtime.sendMessage(msg)) as Reply<T>;
  if (!r.ok) throw Object.assign(new Error(r.error), { code: r.code });
  return r.value;
}

export default defineContentScript({
  matches: ['https://*/*', 'http://*/*'],
  // во фреймы не лезем: iframe с чужого домена мог бы выманить пароль (только по разрешению)
  allFrames: false,
  runAt: 'document_idle',
  main(ctx) {
    let inputs: HTMLInputElement[] = [];
    let forms: LoginForm[] = [];
    const decorated = new WeakSet<HTMLInputElement>();
    let prefs = DEFAULT_PREFS;
    let otpDone = false;

    // --- сбор полей ---
    function visible(el: HTMLElement): boolean {
      const r = el.getBoundingClientRect();
      if (r.width < 8 || r.height < 8) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) < 0.1) return false;
      return (el as any).checkVisibility ? (el as any).checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) : true;
    }

    function labelOf(el: HTMLInputElement): string {
      const byFor = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent : '';
      return [byFor, el.closest('label')?.textContent, el.getAttribute('aria-label')].filter(Boolean).join(' ').slice(0, 80);
    }

    async function scan() {
      inputs = [...document.querySelectorAll<HTMLInputElement>('input')].filter((i) =>
        ['text', 'email', 'tel', 'number', 'password', ''].includes(i.type),
      );
      const formList = [...document.forms];
      const fields: FieldInfo[] = inputs.map((el, index) => ({
        index,
        form: el.form ? formList.indexOf(el.form) : -1,
        type: el.type,
        name: el.name,
        id: el.id,
        autocomplete: el.autocomplete ?? '',
        placeholder: el.placeholder ?? '',
        label: labelOf(el),
        visible: visible(el),
        maxlength: el.maxLength > 0 ? el.maxLength : null,
      }));
      if (!fields.some((f) => f.visible)) return;
      forms = await ask<LoginForm[]>({ type: 'classify', fields }).catch(() => []);
      for (const f of forms) {
        for (const i of [f.username, f.password, ...f.new_passwords, f.otp]) if (i !== null) decorate(inputs[i], f);
      }
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
      }
    }

    // --- значок в поле ---
    function decorate(el: HTMLInputElement, form: LoginForm) {
      if (decorated.has(el)) return;
      decorated.add(el);
      el.addEventListener('focus', () => {
        if (!filling && prefs.menuOnFocus && menu?.anchor !== el) openMenu(el, form, true);
      });
      el.addEventListener('click', (e) => {
        if (e.isTrusted && !filling && prefs.menuOnFocus && !menu) openMenu(el, form, true);
      });
      if (!prefs.icons) return;
      const host = document.createElement('keywarden-icon');
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>
        button{all:unset;cursor:pointer;width:20px;height:20px;border-radius:7px;display:flex;align-items:center;justify-content:center;
          background:#222227;color:#a18bff;font:700 10px Inter,system-ui,sans-serif;box-shadow:0 0 0 1px #2c2d33,0 1px 2px #0003;
          transition:background .12s,transform .12s}
        button:hover{background:#2c2d33;color:#c2b4ff;transform:scale(1.06)}</style><button title="Keywarden" aria-label="Keywarden">K</button>`;
      Object.assign(host.style, { position: 'absolute', zIndex: '2147483646' });
      document.documentElement.appendChild(host);
      const place = () => {
        const r = el.getBoundingClientRect();
        host.style.display = visible(el) ? 'block' : 'none';
        host.style.top = `${r.top + window.scrollY + (r.height - 20) / 2}px`;
        host.style.left = `${r.right + window.scrollX - 28}px`;
      };
      place();
      ctx.setInterval(place, 500);
      // mousedown, а не click: фокус остаётся в поле, меню не мигает
      root.querySelector('button')!.addEventListener('mousedown', (e) => {
        if (!e.isTrusted) return;
        e.preventDefault();
        if (menu?.anchor === el) return closeMenu();
        el.focus();
        openMenu(el, form, false);
      });
    }

    let filling = false;
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
        const c = await ask<{ username: string; password: string }>({ type: 'fill', id: l.id });
        fill(form, c.username, c.password);
      } catch (e) {
        failed(e);
      }
    }

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
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .m{padding:6px;max-height:320px;overflow:auto;border-radius:14px}
        .t{display:flex;align-items:center;gap:7px;font:600 11px Inter,system-ui,sans-serif;color:#8e8e98;padding:4px 8px 7px}
        .t i{font-style:normal;width:16px;height:16px;border-radius:5px;background:#222227;color:#a18bff;display:grid;place-items:center;font-size:9px;font-weight:700}
        .it{display:flex;align-items:center;gap:10px;width:100%;padding:7px 8px;border:0;border-radius:9px;background:transparent;text-align:left}
        .it{transition:background .1s}
        .it.sel,.it:hover{background:#26272d}
        .it:active{transform:scale(.985)}
        .av{flex:none;width:28px;height:28px;border-radius:8px;background:#222227;border:1px solid #2c2d33;display:grid;place-items:center;
          font:600 12px Inter,system-ui,sans-serif;color:#c9c9d1}
        .tx{min-width:0;flex:1}
        .tx b,.tx small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .tx b{font-weight:500;color:#ececef}
        .tx small{color:#8e8e98;font-size:11px;font-weight:400}
        .mono b{font-family:'JetBrains Mono',ui-monospace,monospace;letter-spacing:.5px}
        .e{padding:6px 8px 8px;color:#8e8e98;font-size:12px}</style>
        <div class="m card anim"><div class="t"><i>K</i><span></span></div><div class="l"></div></div>`;
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
        if (!e.composedPath().includes(host) && e.target !== anchor) closeMenu();
      };
      const onBlur = () => setTimeout(() => menu?.anchor === anchor && document.activeElement !== anchor && closeMenu(), 120);
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
        if (e.isTrusted && menu && document.activeElement === menu.anchor && menu.key(e)) {
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
          if (document.activeElement !== el && auto) return;
          return showMenu(el, t('menu_new_password', host), [
            {
              label: pw,
              sub: t('menu_generate_sub'),
              avatar: '✱',
              mono: true,
              pick: () => {
                for (const i of form.new_passwords) setValue(inputs[i], pw);
                toast(t('toast_password_inserted'));
              },
            },
          ]);
        }
        const logins = await siteLogins();
        if (document.activeElement !== el && auto) return;
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
        const code = (e as any).code;
        if (code === 'locked') {
          showMenu(el, `Keywarden · ${host}`, [
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
        } else if (!auto) failed(e);
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

    // --- выбор ключа доступа (тот же вид меню) ---
    function choose(anchor: HTMLElement, logins: Login[], title: string): Promise<Login | null> {
      return new Promise((resolve) => {
        if (logins.length === 0) {
          toast(t('toast_no_entries'));
          return resolve(null);
        }
        let done = false;
        showMenu(
          anchor,
          title,
          logins.map((l) => ({ label: l.title, sub: l.username || l.group, pick: () => ((done = true), resolve(l)) })),
        );
        const m = menu!;
        const close = m.close;
        m.close = () => {
          close();
          if (!done) resolve(null);
        };
      });
    }

    function toast(text: string) {
      const host = document.createElement('keywarden-toast');
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .card{position:fixed;top:16px;right:16px;z-index:2147483647;padding:10px 14px;max-width:360px;display:flex;gap:8px;align-items:center}
        .card::before{content:"K";flex:none;width:20px;height:20px;border-radius:7px;background:#222227;color:#a18bff;
          font:700 10px Inter,system-ui,sans-serif;display:grid;place-items:center}</style><div class="card anim"></div>`;
      root.querySelector('div')!.textContent = text;
      document.documentElement.appendChild(host);
      ctx.setTimeout(() => host.remove(), 4000);
    }

    // --- предложение сохранить пароль ---
    function captureSubmit(form?: LoginForm) {
      const f = form ?? formFor();
      if (!f) return;
      const pwIdx = f.password ?? f.new_passwords[0] ?? null;
      if (pwIdx === null) return;
      const password = inputs[pwIdx]?.value;
      const username = f.username !== null ? inputs[f.username].value : '';
      if (password) ask({ type: 'submitted', username, password }).then((r) => r && showSave()).catch(() => {});
    }

    async function showSave() {
      const p = await ask<{ site: string; username: string; password: string; state: string } | null>({ type: 'pendingSave' }).catch(() => null);
      if (!p || document.querySelector('keywarden-save')) return;
      const host = document.createElement('keywarden-save');
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>${CSS_BASE}
        .b{position:fixed;top:16px;right:16px;z-index:2147483647;width:340px;overflow:hidden}
        .h{display:flex;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid #26262b}
        .logo{flex:none;width:28px;height:28px;border-radius:9px;background:#222227;border:1px solid #2c2d33;color:#a18bff;
          font:700 12px Inter,system-ui,sans-serif;display:grid;place-items:center}
        .title{font-weight:600}
        .site{font-size:12px}
        .who{padding:10px 14px;display:flex;justify-content:space-between;align-items:center;gap:8px;min-height:40px;box-sizing:border-box}
        .who + .who{border-top:1px solid #25252a}
        .who b{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .pw{display:flex;align-items:center;gap:6px;min-width:0}
        .pw b{font-family:'JetBrains Mono',ui-monospace,monospace;letter-spacing:.5px}
        .pw b.dots{letter-spacing:2px;color:#c9c9d1}
        .eye{padding:4px;display:grid;place-items:center;border-radius:6px}
        .eye svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
        .r{display:flex;gap:6px;align-items:center;padding:10px 14px;border-top:1px solid #26262b;background:#141417}
        .sp{flex:1}</style>
        <div class="b card anim">
          <div class="h"><div class="logo">K</div><div><div class="title"></div><div class="site muted"></div></div></div>
          <div class="who"><span class="muted">${t('username')}</span><b class="user"></b></div>
          <div class="who"><span class="muted">${t('password')}</span>
            <span class="pw"><b class="dots"></b><button class="ghost eye"></button></span></div>
          <div class="r"><button class="ghost never">${t('never_here')}</button><span class="sp"></span>
            <button class="n">${t('not_now')}</button><button class="p primary"></button></div>
        </div>`;
      const changed = p.state === 'changed';
      root.querySelector('.title')!.textContent = t(changed ? 'prompt_update_keywarden' : 'prompt_save_keywarden');
      root.querySelector('.site')!.textContent = p.site;
      root.querySelector('.who b.user')!.textContent = p.username || t('no_username');
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
        ask({ type: 'save', accept }).then(() => accept && toast(t('toast_saved_keywarden'))).catch((err) => toast((err as Error).message));
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
      const formEl = e.target as HTMLFormElement;
      const idx = [...document.forms].indexOf(formEl);
      captureSubmit(forms.find((f) => f.form === idx));
    }, true);
    // SPA без <form>: Enter в поле пароля или клик по кнопке рядом
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target instanceof HTMLInputElement && e.target.type === 'password') captureSubmit(formFor(e.target));
    }, true);
    document.addEventListener('click', (e) => {
      const b = (e.target as Element)?.closest?.('button,[type=submit],[role=button]');
      if (b && forms.some((f) => f.password !== null || f.new_passwords.length)) captureSubmit();
    }, true);

    // --- окно Keywarden на странице: скруглённая панель с popup.html внутри iframe ---
    let panel: { host: HTMLElement; frame: HTMLIFrameElement; close: () => void } | null = null;
    function togglePanel() {
      if (panel) return panel.close();
      closeMenu();
      const host = document.createElement('keywarden-panel');
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>
        .p{position:fixed;top:10px;right:12px;z-index:2147483647;width:440px;max-width:calc(100vw - 24px);height:640px;max-height:calc(100vh - 20px);
          border-radius:16px;overflow:hidden;background:#141417;border:1px solid #2a2a2f;
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
      const f = formFor(document.activeElement instanceof HTMLInputElement ? document.activeElement : undefined);
      if (msg.type === 'triggerFill' && f) {
        const el = inputs[f.otp ?? f.password ?? f.username ?? f.new_passwords[0]];
        if (el) quickFill(el, f);
      }
      if (msg.type === 'fillWith' && f) fill(f, msg.username, msg.password);
      if (msg.type === 'togglePanel') togglePanel();
      if (msg.type === 'fillNew') {
        // поля нового пароля формы, иначе поле пароля в фокусе
        const nf = forms.find((x) => x.new_passwords.length);
        const targets = nf
          ? nf.new_passwords.map((i) => inputs[i])
          : document.activeElement instanceof HTMLInputElement && document.activeElement.type === 'password'
            ? [document.activeElement]
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
      try {
        if (kind === 'create') {
          return reply(id, { ok: true, credential: await ask({ type: 'passkeyCreate', options }) });
        }
        const candidates = await ask<Login[]>({ type: 'passkeyList', options });
        if (candidates.length === 0) return reply(id, { fallback: true });
        const pick = candidates.length === 1 ? candidates[0] : await choose(document.body, candidates, t('passkey'));
        if (!pick) return reply(id, { fallback: true });
        reply(id, { ok: true, credential: await ask({ type: 'passkeyGet', options, id: pick.id }) });
      } catch (err) {
        const er = err as Error & { code?: string };
        if (er.code === 'locked') toast(t('toast_passkey_locked'));
        if (isFallback(er)) return reply(id, { fallback: true });
        reply(id, { ok: false, error: er.message, name: er.message.startsWith('InvalidStateError') ? 'InvalidStateError' : 'NotAllowedError' });
      }
    });

    loadPrefs()
      .then((p) => (prefs = p))
      .finally(() => scan().then(showSave));
    browser.storage.onChanged.addListener((c) => {
      if (c.prefs) loadPrefs().then((p) => (prefs = p));
    });
    let timer: number | undefined;
    new MutationObserver(() => {
      clearTimeout(timer);
      timer = ctx.setTimeout(scan, 400) as unknown as number;
    }).observe(document.documentElement, { childList: true, subtree: true });
  },
});
