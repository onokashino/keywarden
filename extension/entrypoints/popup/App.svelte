<script lang="ts">
  import type { Filter, Folder, GenOptions, Item, Login, Msg, Reply, Status } from '../../utils/messages';
  import { DEFAULT_PREFS, loadPrefs, savePrefs, type Prefs } from '../../utils/prefs';
  import Select from './Select.svelte';
  import { t } from '../../utils/i18n';
  import { fade, fly, scale } from 'svelte/transition';
  import { cubicOut } from 'svelte/easing';

  // системное «уменьшить движение»: все переходы мгновенные
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ms = (d: number) => (still ? 0 : d);
  // направление перехода между экранами: вперёд (запись, новая) справа, назад слева
  let back = $state(false);

  async function ask<T>(msg: Msg): Promise<T> {
    const r = (await browser.runtime.sendMessage(msg)) as Reply<T>;
    if (!r.ok) throw Object.assign(new Error(r.error), { code: r.code });
    return r.value;
  }

  type Tab = 'vault' | 'generator' | 'settings';
  type View = { kind: 'list' } | { kind: 'item' } | { kind: 'new' };
  let tab = $state<Tab>('vault');
  let view = $state<View>({ kind: 'list' });
  let status = $state<Status | null>(null);
  let loading = $state(true);
  let listError = $state('');
  let site = $state<Login[]>([]);
  let all = $state<Login[]>([]);
  let query = $state('');
  let host = $state('');
  let pageUrl = $state('');
  let item = $state<Item | null>(null);
  let left = $state(0);
  let toast = $state('');
  let busy = $state(false);
  let offer = $state<{ site: string; username: string; state: string } | null>(null);
  let prefs = $state<Prefs>({ ...DEFAULT_PREFS });
  let menuFor = $state<string | null>(null);
  let searchEl = $state<HTMLInputElement | null>(null);
  let brokenIcons = $state<Record<string, boolean>>({});

  const ready = $derived(!!status?.connected && !!status.associated && !status.locked);
  // открыто панелью на странице (iframe), а не окном Chrome
  const embedded = location.hash === '#panel';
  if (embedded) document.documentElement.classList.add('panel');
  function closeUi() {
    if (embedded) parent.postMessage({ kw: 'close-panel' }, '*');
    else window.close();
  }
  const firefox = import.meta.env.BROWSER === 'firefox';

  // --- иконки ---
  function icon(url?: string): string | null {
    // только веб-адреса; ssh://, otpauth:// и прочее получают иконку типа
    if (firefox || !url || (url.includes('://') && !/^https?:\/\//.test(url))) return null;
    const u = new URL(browser.runtime.getURL('/_favicon/' as '/popup.html'));
    u.searchParams.set('pageUrl', url.includes('://') ? url : `https://${url}`);
    u.searchParams.set('size', '32');
    return u.toString();
  }
  const letter = (t: string) => (t || '?').trim().slice(0, 1).toUpperCase();

  function say(text: string) {
    toast = text;
    setTimeout(() => toast === text && (toast = ''), 2000);
  }

  // --- загрузка ---
  async function refresh() {
    loading = true;
    prefs = await loadPrefs();
    status = await ask<Status>({ type: 'status' }).catch((e) => ({ connected: false, associated: false, locked: false, error: e.message }));
    const [t] = await browser.tabs.query({ active: true, currentWindow: true });
    pageUrl = t?.url?.startsWith('http') ? t.url : '';
    try {
      host = pageUrl ? new URL(pageUrl).hostname : '';
    } catch {
      host = '';
    }
    if (!ready) return void (loading = false);
    const [o, s] = await Promise.all([
      ask<typeof offer>({ type: 'pendingSave' }).catch(() => null),
      ask<Login[]>({ type: 'logins' }).catch(() => [] as Login[]),
    ]);
    offer = o;
    site = s;
    await Promise.all([search(), loadFacets()]);
    loading = false;
    searchEl?.focus();
  }

  // --- фильтры: тип, папка, тег ---
  const KINDS: [string, string][] = [
    ['login', t('kind_login')],
    ['card', t('kind_card')],
    ['identity', t('kind_identity')],
    ['note', t('kind_note')],
    ['ssh_key', 'SSH'],
    ['passkey', t('kind_passkey')],
    ['crypto_wallet', t('kind_crypto_wallet')],
  ];
  let filter = $state<Filter>({});
  let showFilters = $state(false);
  let folders = $state<Folder[]>([]);
  let tags = $state<[string, number][]>([]);
  const filtered = $derived(!!(filter.kind || filter.group || filter.tag));
  const filterCount = $derived([filter.kind, filter.group, filter.tag].filter(Boolean).length);

  async function search() {
    try {
      all = await ask<Login[]>({ type: 'search', query, filter: $state.snapshot(filter) });
      listError = '';
    } catch (e) {
      all = [];
      listError = (e as Error).message;
    }
  }
  async function loadFacets() {
    const f = await ask<{ folders: Folder[]; tags: [string, number][] }>({ type: 'facets' }).catch(() => null);
    if (f) ({ folders, tags } = f);
  }
  function setFilter(f: Filter) {
    const next: Filter = { ...$state.snapshot(filter), ...f };
    for (const k of Object.keys(next) as (keyof Filter)[]) if (!next[k]) delete next[k];
    filter = next;
    search();
  }

  let timer: ReturnType<typeof setTimeout>;
  function onQuery() {
    clearTimeout(timer);
    timer = setTimeout(search, 120);
  }

  const onSite = (id: string) => site.some((l) => l.id === id);
  const others = $derived(query || filtered ? all : all.filter((l) => !onSite(l.id)));

  // --- карточка записи ---
  async function open(id: string) {
    menuFor = null;
    try {
      item = await ask<Item>({ type: 'item', id });
      left = item.totp?.[1] ?? 0;
      back = false;
      view = { kind: 'item' };
    } catch (e) {
      say((e as Error).message);
    }
  }
  // код 2FA: по нулю берём новый
  $effect(() => {
    if (view.kind !== 'item' || !item?.totp) return;
    const t = setInterval(async () => {
      left -= 1;
      if (left <= 0 && item) {
        const fresh = await ask<Item>({ type: 'item', id: item.id }).catch(() => null);
        if (fresh) {
          item = fresh;
          left = fresh.totp?.[1] ?? 0;
        }
      }
    }, 1000);
    return () => clearInterval(t);
  });

  // какая кнопка только что скопировала: иконка на секунду становится галочкой
  let copied = $state('');
  async function copy(id: string, field: 'username' | 'password' | 'totp') {
    menuFor = null;
    try {
      await ask({ type: 'copy', id, field });
      copied = `${id}:${field}`;
      setTimeout(() => copied === `${id}:${field}` && (copied = ''), 1200);
      say(t(`copied_${field}`));
    } catch (e) {
      say((e as Error).message);
    }
  }

  // публичный адрес кошелька: копируем сами, демону он не нужен
  async function copyAddress(addr: string) {
    await navigator.clipboard.writeText(addr);
    copied = `addr:${addr}`;
    setTimeout(() => copied === `addr:${addr}` && (copied = ''), 1200);
    say(t('address_copied'));
  }

  async function run(msg: Msg, done?: string) {
    busy = true;
    menuFor = null;
    try {
      await ask(msg);
      if (done) say(done);
      if (msg.type === 'fill' || msg.type === 'fillNew') closeUi();
    } catch (e) {
      say((e as Error).message);
    } finally {
      busy = false;
      if (['associate', 'openUnlock', 'save', 'neverSave', 'lock'].includes(msg.type)) refresh();
    }
  }

  const openSite = (url: string) => browser.tabs.create({ url: url.includes('://') ? url : `https://${url}` });

  // --- новая запись ---
  let draft = $state({ title: '', username: '', password: '', url: '', show: false });
  async function startNew() {
    menuFor = null;
    draft = { title: host, username: '', password: '', url: pageUrl ? new URL(pageUrl).origin : '', show: false };
    back = false;
    view = { kind: 'new' };
    draft.password = await ask<string>({ type: 'generate' }).catch(() => '');
  }
  async function createItem() {
    if (!draft.url || !draft.password) return say(t('need_url_password'));
    busy = true;
    try {
      await ask({ type: 'create', title: draft.title, username: draft.username, password: draft.password, url: draft.url });
      say(t('entry_saved'));
      back = true;
      view = { kind: 'list' };
      await refresh();
    } catch (e) {
      say((e as Error).message);
    } finally {
      busy = false;
    }
  }

  // --- генератор ---
  let generated = $state('');
  let entropy = $state(0);
  let phrase = $state(false);
  let pw = $state({ length: 20, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: true });
  let ph = $state({ words: 5, separator: '-', capitalize: true, number: true });
  let genTimer: ReturnType<typeof setTimeout>;
  const strength = $derived(
    entropy >= 100 ? [t('strength_excellent'), 4] : entropy >= 70 ? [t('strength_strong'), 3] : entropy >= 50 ? [t('strength_fair'), 2] : [t('strength_weak'), 1],
  );
  const chars = $derived([...generated].map((c) => ({ c, k: /[0-9]/.test(c) ? 'd' : /[a-zA-Zа-яА-ЯёЁ]/.test(c) ? '' : 's' })));

  async function generate() {
    const options: GenOptions = phrase ? { mode: 'passphrase', ...ph } : { mode: 'password', ...pw };
    try {
      const r = await ask<{ password: string; entropy: number } | undefined>({ type: 'generateWith', options });
      if (!r?.password) throw new Error(t('err_generator'));
      generated = r.password;
      entropy = r.entropy;
    } catch (e) {
      say((e as Error).message);
    }
  }
  function regenSoon() {
    clearTimeout(genTimer);
    genTimer = setTimeout(generate, 60);
  }
  async function loadGen() {
    const { genOptions } = (await browser.storage.local.get('genOptions')) as { genOptions?: { mode?: string } & Record<string, any> };
    if (genOptions?.mode === 'passphrase') {
      phrase = true;
      const { mode, ...rest } = genOptions;
      ph = { ...ph, ...rest };
    } else if (genOptions?.mode === 'password') {
      const { mode, ...rest } = genOptions;
      pw = { ...pw, ...rest };
    }
    generate();
  }
  async function copyGenerated() {
    await navigator.clipboard.writeText(generated);
    say(t('password_copied'));
  }

  async function setPref<K extends keyof Prefs>(key: K, value: Prefs[K]) {
    prefs = { ...prefs, [key]: value };
    await savePrefs($state.snapshot(prefs) as Prefs);
  }

  $effect(() => {
    refresh();
  });
  $effect(() => {
    if (tab === 'generator' && !generated && ready) loadGen();
  });
</script>

{#snippet svg(name: string)}
  <svg viewBox="0 0 24 24" aria-hidden="true">
    {#if name === 'card'}<rect x="2" y="5" width="20" height="14" rx="2" /><path d="M2 10h20" />
    {:else if name === 'identity'}<rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="11" r="2.5" /><path d="M5.5 17a3.5 3.5 0 0 1 7 0M15 9h3M15 13h3" />
    {:else if name === 'note'}<path d="M15 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h6M8 13h8M8 17h5" />
    {:else if name === 'ssh_key'}<rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M12 15h5" />
    {:else if name === 'passkey'}<path d="M12 11v3M8 7a6 6 0 0 1 10 4.5V13M6 11a6 6 0 0 1 .5-2.4M9 21a12 12 0 0 1-3-7M12 18v3M15 14v1a9 9 0 0 1-1 4" />
    {:else if name === 'login'}<circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 9.3-9.3M17 6l2 2M14 9l2 2" />
    {:else if name === 'user'}<circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" />
    {:else if name === 'timer'}<circle cx="12" cy="13" r="8" /><path d="M12 9v4l2 2M10 2h4" />
    {:else if name === 'copy'}<rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
    {:else if name === 'open'}<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    {:else if name === 'back'}<path d="m15 18-6-6 6-6" />
    {:else if name === 'search'}<circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
    {:else if name === 'filter'}<path d="M3 5h18M6 12h12M10 19h4" />
    {:else if name === 'plus'}<path d="M12 5v14M5 12h14" />
    {:else if name === 'lock'}<rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" />
    {:else if name === 'more'}<circle cx="5" cy="12" r="1.2" /><circle cx="12" cy="12" r="1.2" /><circle cx="19" cy="12" r="1.2" />
    {:else if name === 'fill'}<path d="M4 12h12M12 6l6 6-6 6M20 4v16" />
    {:else if name === 'regen'}<path d="M21 12a9 9 0 1 1-3-6.7L21 8" /><path d="M21 3v5h-5" />
    {:else if name === 'eye'}<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" />
    {:else if name === 'vault'}<rect x="3" y="4" width="18" height="16" rx="3" /><circle cx="12" cy="12" r="3" /><path d="M12 9V7M12 17v-2" />
    {:else if name === 'sliders'}<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12" /><circle cx="16" cy="6" r="2" /><circle cx="10" cy="12" r="2" /><circle cx="18" cy="18" r="2" />
    {:else if name === 'folder'}<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    {:else if name === 'tag'}<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18" />
    {:else if name === 'wallet' || name === 'crypto_wallet'}<path d="M19 7V5a2 2 0 0 0-2-2H5a2 2 0 0 0 0 4h15a1 1 0 0 1 1 1v4h-3a2 2 0 0 0 0 4h3a1 1 0 0 0 1-1v-2" /><path d="M3 5v14a2 2 0 0 0 2 2h15a1 1 0 0 0 1-1v-4" />{/if}
  </svg>
{/snippet}

{#snippet avatar(l: { id: string; title: string; url?: string; kind?: string }, big = false)}
  {@const src = brokenIcons[l.id] ? null : icon(l.url)}
  <span class="av" class:big>
    {#if src}
      <img {src} alt="" onerror={() => (brokenIcons[l.id] = true)} />
    {:else if l.kind && l.kind !== 'login'}
      {@render svg(l.kind)}
    {:else}
      {letter(l.title)}
    {/if}
  </span>
{/snippet}

{#snippet copyIcon(key: string)}
  {#if copied === key}
    <span class="ok" in:scale={{ start: 0.5, duration: ms(180), easing: cubicOut }}>
      <svg viewBox="0 0 24 24"><path d="m5 12 5 5 9-10" /></svg>
    </span>
  {:else}
    {@render svg('copy')}
  {/if}
{/snippet}

{#snippet row(l: Login, suggest: boolean, i = 0)}
  <div in:fly={{ y: 6, duration: ms(200), delay: ms(Math.min(i, 10) * 22), easing: cubicOut }} class="item" role="button" tabindex="0" onclick={() => open(l.id)} onkeydown={(e) => e.key === 'Enter' && open(l.id)}>
    {@render avatar(l)}
    <span class="who">
      <b>{l.title || t('untitled')}</b>
      <small>{l.username || l.group || ' '}</small>
    </span>
    {#if suggest}
      <button class="outline small" disabled={busy} onclick={(e) => (e.stopPropagation(), run({ type: 'fill', id: l.id }))}>{t('fill')}</button>
    {/if}
    <span class="morewrap">
      <button class="icon" title={t('actions')} aria-haspopup="menu" onclick={(e) => (e.stopPropagation(), (menuFor = menuFor === l.id ? null : l.id))}>
        {@render svg('more')}
      </button>
      {#if menuFor === l.id}
        <div class="pop" in:scale={{ start: 0.94, duration: ms(130), easing: cubicOut }} role="menu" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.key === 'Escape' && (menuFor = null)}>
          {#if onSite(l.id)}
            <button role="menuitem" onclick={() => run({ type: 'fill', id: l.id })}>{@render svg('fill')}{t('fill')}</button>
          {/if}
          {#if l.kind === 'crypto_wallet'}
            <button role="menuitem" onclick={() => open(l.id)}>{@render svg('wallet')}{t('wallet_addresses')}</button>
          {:else}
          {#if l.username}<button role="menuitem" onclick={() => copy(l.id, 'username')}>{@render svg('user')}{t('copy_username')}</button>{/if}
          <button role="menuitem" onclick={() => copy(l.id, 'password')}>{@render svg('login')}{t('copy_password')}</button>
          {/if}
          {#if l.has_otp}<button role="menuitem" onclick={() => copy(l.id, 'totp')}>{@render svg('timer')}{t('copy_totp')}</button>{/if}
          {#if l.url && /^https?:/.test(l.url)}<button role="menuitem" onclick={() => openSite(l.url!)}>{@render svg('open')}{t('open_site')}</button>{/if}
        </div>
      {/if}
    </span>
  </div>
{/snippet}

{#snippet skeleton(n: number)}
  <section class="card">
    {#each Array(n) as _, i (i)}
      <div class="item sk"><span class="av"></span><span class="who"><i></i><i class="short"></i></span></div>
    {/each}
  </section>
{/snippet}


<svelte:window
  onkeydown={(e) => e.key === 'Escape' && embedded && !menuFor && closeUi()}
  onpointerdown={(e) => menuFor && !(e.target as Element).closest?.('.morewrap') && (menuFor = null)}
/>

<div class="app">
  {#if view.kind === 'item' && item}
   <div class="screen" in:fly={{ x: 28, duration: ms(220), easing: cubicOut }}>
    <header class="bar">
      <button class="icon" title={t('back')} onclick={() => ((back = true), (view = { kind: 'list' }))}>{@render svg('back')}</button>
      <span class="title">{t('view_entry')}</span>
    </header>
    <main class="scroll">
      <div class="hero">
        {@render avatar(item, true)}
        <div class="who">
          <b>{item.title || t('untitled')}</b>
          <small>{item.group || t('vault')}</small>
        </div>
      </div>
      <h2>{t('login_details')}</h2>
      <section class="card">
        {#if item.username}
          <div class="field">
            <span><small>{t('username')}</small><span class="val">{item.username}</span></span>
            <button class="icon" title={t('copy')} onclick={() => copy(item!.id, 'username')}>{@render copyIcon(`${item!.id}:username`)}</button>
          </div>
        {/if}
        {#if item.has_password}
          <div class="field">
            <span><small>{t('password')}</small><span class="val mono">••••••••••••</span></span>
            <button class="icon" title={t('copy')} onclick={() => copy(item!.id, 'password')}>{@render copyIcon(`${item!.id}:password`)}</button>
          </div>
        {/if}
        {#if item.totp}
          <div class="field">
            <span>
              <small>{t('totp_code')}</small>
              <span class="val mono code">{item.totp[0].slice(0, Math.ceil(item.totp[0].length / 2))} {item.totp[0].slice(Math.ceil(item.totp[0].length / 2))}</span>
            </span>
            <span class="ring" class:urgent={left <= 5} style:--p={`${(left / item.totp[2]) * 100}%`}>{left}</span>
            <button class="icon" title={t('copy')} onclick={() => copy(item!.id, 'totp')}>{@render copyIcon(`${item!.id}:totp`)}</button>
          </div>
        {/if}
        {#if !item.username && !item.has_password && !item.totp}
          <p class="hint pad">{t('no_login_password')}</p>
        {/if}
      </section>
      {#if item.addresses?.length}
        <h2>{t('receive_addresses')}</h2>
        <section class="card">
          {#each item.addresses as [label, addr], i (i)}
            <div class="field">
              <span><small>{label || t('address')}</small><span class="val mono">{addr}</span></span>
              <button class="icon" title={t('copy')} onclick={() => copyAddress(addr)}>
                {@render copyIcon(`addr:${addr}`)}
              </button>
            </div>
          {/each}
        </section>
        <p class="hint">{t('wallet_hint')}</p>
      {/if}
      {#if item.url}
        <h2>{t('site')}</h2>
        <section class="card">
          <div class="field">
            <span><small>{t('address')}</small><span class="val">{item.url}</span></span>
            {#if /^https?:/.test(item.url)}
              <button class="icon" title={t('open')} onclick={() => openSite(item!.url)}>{@render svg('open')}</button>
            {/if}
          </div>
        </section>
      {/if}
    </main>
    {#if onSite(item.id)}
      <footer class="actions">
        <button class="primary wide" disabled={busy} onclick={() => run({ type: 'fill', id: item!.id })}>{t('fill_on_page')}</button>
      </footer>
    {/if}
   </div>
  {:else if view.kind === 'new'}
   <div class="screen" in:fly={{ x: 28, duration: ms(220), easing: cubicOut }}>
    <header class="bar">
      <button class="icon" title={t('back')} onclick={() => ((back = true), (view = { kind: 'list' }))}>{@render svg('back')}</button>
      <span class="title">{t('new_entry')}</span>
    </header>
    <main class="scroll">
      <h2>{t('login_details')}</h2>
      <section class="card form">
        <label class="input"><small>{t('title')}</small><input bind:value={draft.title} placeholder={t('title_placeholder')} /></label>
        <label class="input"><small>{t('username')}</small><input bind:value={draft.username} placeholder={t('username_placeholder')} autocomplete="off" /></label>
        <div class="input">
          <small>{t('password')}</small>
          <span class="with">
            <input class="mono" type={draft.show ? 'text' : 'password'} bind:value={draft.password} autocomplete="new-password" />
            <button class="icon" title={t('show')} onclick={() => (draft.show = !draft.show)}>{@render svg('eye')}</button>
            <button class="icon" title={t('generate')} onclick={async () => (draft.password = await ask<string>({ type: 'generate' }))}>{@render svg('regen')}</button>
          </span>
        </div>
      </section>
      <h2>{t('site')}</h2>
      <section class="card form">
        <label class="input"><small>{t('address')}</small><input bind:value={draft.url} placeholder="https://example.com" /></label>
      </section>
      <p class="hint">{t('new_entry_hint')}</p>
    </main>
    <footer class="actions">
      <button onclick={() => ((back = true), (view = { kind: 'list' }))}>{t('cancel')}</button>
      <button class="primary grow" disabled={busy} onclick={createItem}>{t('save')}</button>
    </footer>
   </div>
  {:else}
   <div class="screen" in:fly={{ x: back ? -20 : 0, y: back ? 0 : 4, duration: ms(back ? 220 : 160), easing: cubicOut }}>
    <header class="bar">
      <span class="logo">K</span>
      <span class="title">{t(tab)}</span>
      {#if tab === 'vault' && ready}
        <button class="primary small" onclick={startNew}>{@render svg('plus')}{t('new_short')}</button>
      {/if}
      {#if ready}
        <button class="icon" title={t('lock_vault')} onclick={() => run({ type: 'lock' }, t('vault_locked'))}>{@render svg('lock')}</button>
      {/if}
    </header>

    {#if tab === 'vault' && ready}
      <div class="searchbar">
        <label class="search">
          {@render svg('search')}
          <input bind:this={searchEl} bind:value={query} oninput={onQuery} placeholder={t('search_placeholder')} />
        </label>
        <button class="icon fbtn" class:on={showFilters || filtered} title={t('filters')} onclick={() => (showFilters = !showFilters)}>
          {@render svg('filter')}
          {#if filterCount}<span class="badge">{filterCount}</span>{/if}
        </button>
      </div>
      {#if showFilters}
        <div class="filters">
          <Select
            value={filter.kind ?? ''}
            options={[{ value: '', label: t('all_types') }, ...KINDS.map(([k, label]) => ({ value: k, label }))]}
            onchange={(v) => setFilter({ kind: v || undefined })}
          >
            {#snippet icon()}{@render svg('login')}{/snippet}
          </Select>
          <Select
            value={filter.group ?? ''}
            options={[{ value: '', label: t('all_folders') }, ...folders.map((f) => ({ value: f.id, label: f.name, depth: f.depth, count: f.count }))]}
            onchange={(v) => setFilter({ group: v || undefined })}
          >
            {#snippet icon()}{@render svg('folder')}{/snippet}
          </Select>
          <Select
            value={filter.tag ?? ''}
            options={[{ value: '', label: t('all_tags') }, ...tags.map(([t, n]) => ({ value: t, label: `#${t}`, count: n }))]}
            onchange={(v) => setFilter({ tag: v || undefined })}
          >
            {#snippet icon()}{@render svg('tag')}{/snippet}
          </Select>
          {#if filtered}<button class="ghost small" onclick={() => (filter = {}, search())}>{t('reset')}</button>{/if}
        </div>
      {/if}
    {/if}

    {#key tab}
    <main class="scroll" in:fly={{ y: 6, duration: ms(180), easing: cubicOut }}>
      {#if tab === 'vault'}
        {#if status === null || (loading && !ready && !status)}
          {@render skeleton(3)}
        {:else if !status.connected}
          <div class="empty">
            <span class="big">!</span>
            <b>{t('no_connection')}</b>
            <p class="muted">{t('no_connection_hint')}</p>
            {#if status.error}<p class="err">{status.error}</p>{/if}
          </div>
        {:else if !status.associated}
          <div class="empty">
            <span class="big">K</span>
            <b>{t('connect_title')}</b>
            <p class="muted">{t('connect_hint')}</p>
            <button class="primary" disabled={busy} onclick={() => run({ type: 'associate' }, t('connected'))}>{t('connect')}</button>
          </div>
        {:else if status.locked}
          <div class="empty">
            <span class="big">{@render svg('lock')}</span>
            <b>{t('vault_locked')}</b>
            <p class="muted">{t('locked_hint')}</p>
            <button class="primary" disabled={busy} onclick={() => run({ type: 'openUnlock' })}>{t('unlock')}</button>
          </div>
        {:else}
          {#if offer}
            <section class="card offer">
              <div class="who pad">
                <b>{t(offer.state === 'changed' ? 'offer_update' : 'offer_save')}</b>
                <small>{offer.username || t('no_username')} · {offer.site}</small>
              </div>
              <div class="foot">
                <button class="ghost" disabled={busy} onclick={() => run({ type: 'neverSave' }, t('never_site_done'))}>{t('never')}</button>
                <span class="sp"></span>
                <button disabled={busy} onclick={() => run({ type: 'save', accept: false })}>{t('not_now')}</button>
                <button class="primary" disabled={busy} onclick={() => run({ type: 'save', accept: true }, t('saved'))}>{t('save')}</button>
              </div>
            </section>
          {/if}
          {#if !query && !filtered && host}
            <h2>{t('for_this_page')}<span class="count">{site.length || ''}</span></h2>
            {#if loading}
              {@render skeleton(1)}
            {:else if site.length}
              <section class="card">{#each site as l, i (l.id)}{@render row(l, true, i)}{/each}</section>
            {:else}
              <section class="card emptycard">
                <span class="muted">{t('no_entries_for', host)}</span>
                <button class="outline small" onclick={startNew}>{@render svg('plus')}{t('add')}</button>
              </section>
            {/if}
          {/if}
          <h2>{t(query || filtered ? 'found' : 'all_entries')}<span class="count">{loading ? '' : others.length}</span></h2>
          {#if loading}
            {@render skeleton(4)}
          {:else if listError}
            <p class="err pad">{t('load_failed', listError)}</p>
          {:else if others.length}
            <section class="card">{#each others as l, i (l.id)}{@render row(l, false, i)}{/each}</section>
          {:else}
            <p class="hint pad">{t(query || filtered ? 'nothing_found' : 'no_other_entries')}</p>
          {/if}
        {/if}
      {:else if tab === 'generator' && !ready}
        <div class="empty">
          <span class="big">{@render svg('lock')}</span>
          <b>{t(status?.connected ? 'vault_locked' : 'no_connection')}</b>
          <p class="muted">{t('generator_locked_hint')}</p>
          {#if status?.connected}<button class="primary" disabled={busy} onclick={() => run({ type: 'openUnlock' })}>{t('unlock')}</button>{/if}
        </div>
      {:else if tab === 'generator'}
        <section class="card gen">
          <div class="pw mono" title={t('gen_colors_hint')}>
            {#key generated}
              {#each chars as ch, i (i)}<span class={ch.k} in:fade={{ duration: ms(140), delay: ms(Math.min(i, 40) * 7) }}>{ch.c}</span>{/each}
            {/key}
          </div>
          <div class="meter" class:hidden={!generated}>
            {#each [1, 2, 3, 4] as n (n)}<i class:on={n <= Number(strength[1])} data-l={strength[1]}></i>{/each}
            <span>{t('strength_bits', strength[0], Math.round(entropy))}</span>
          </div>
          <div class="foot">
            <button class="icon" title={t('another_one')} onclick={generate}>{@render svg('regen')}</button>
            <button class="ghost" disabled={!generated} onclick={() => run({ type: 'fillNew', password: generated }, t('inserted_new_password'))}>{t('insert_into_field')}</button>
            <span class="sp"></span>
            <button class="primary" disabled={!generated} onclick={copyGenerated}>{t('copy')}</button>
          </div>
        </section>
        <div class="seg">
          <button class:active={!phrase} onclick={() => ((phrase = false), generate())}>{t('password')}</button>
          <button class:active={phrase} onclick={() => ((phrase = true), generate())}>{t('passphrase')}</button>
        </div>
        <section class="card">
          {#if !phrase}
            <div class="field range">
              <span><b>{t('length')}</b></span>
              <button class="icon step" title={t('shorter')} onclick={() => ((pw.length = Math.max(6, pw.length - 1)), generate())}>−</button>
              <input type="range" min="6" max="64" bind:value={pw.length} oninput={regenSoon} />
              <button class="icon step" title={t('longer')} onclick={() => ((pw.length = Math.min(64, pw.length + 1)), generate())}>+</button>
              <span class="num">{pw.length}</span>
            </div>
            <div class="field">
              <span class="sets">
                {#each [['upper', 'A-Z', t('set_upper')], ['lower', 'a-z', t('set_lower')], ['digits', '0-9', t('set_digits')], ['symbols', '!@#', t('set_symbols')]] as [k, label, hint] (k)}
                  {@const on = pw[k as 'upper']}
                  {@const last = on && [pw.upper, pw.lower, pw.digits, pw.symbols].filter(Boolean).length === 1}
                  <button class="set" class:on title={last ? t('need_one_set') : hint} disabled={last}
                    onclick={() => ((pw[k as 'upper'] = !on), generate())}>
                    {#if on}<svg viewBox="0 0 24 24"><path d="m5 12 5 5 9-10" /></svg>{/if}{label}
                  </button>
                {/each}
              </span>
            </div>
            <label class="field toggle"><span><b>{t('no_lookalikes')}</b><small>{t('no_lookalikes_hint')}</small></span><input type="checkbox" class="switch" bind:checked={pw.exclude_ambiguous} onchange={generate} /></label>
          {:else}
            <div class="field range">
              <span><b>{t('words')}</b></span>
              <input type="range" min="3" max="12" bind:value={ph.words} oninput={regenSoon} />
              <span class="num">{ph.words}</span>
            </div>
            <label class="field toggle"><span><b>{t('capitalize')}</b><small>{t('capitalize_hint')}</small></span><input type="checkbox" class="switch" bind:checked={ph.capitalize} onchange={generate} /></label>
            <label class="field toggle"><span><b>{t('add_digit')}</b><small>{t('add_digit_hint')}</small></span><input type="checkbox" class="switch" bind:checked={ph.number} onchange={generate} /></label>
            <div class="field">
              <span><b>{t('separator')}</b></span>
              <span class="chips">
                {#each ['-', '.', '_', ' '] as sep (sep)}
                  <button class:active={ph.separator === sep} onclick={() => ((ph.separator = sep), generate())}>{sep === ' ' ? t('space') : sep}</button>
                {/each}
              </span>
            </div>
          {/if}
        </section>
      {:else}
        <h2>{t('section_autofill')}</h2>
        <section class="card">
          <label class="field toggle"><span><b>{t('pref_icons')}</b><small>{t('pref_icons_hint')}</small></span><input type="checkbox" class="switch" checked={prefs.icons} onchange={(e) => setPref('icons', e.currentTarget.checked)} /></label>
          <label class="field toggle"><span><b>{t('pref_menu')}</b><small>{t('pref_menu_hint')}</small></span><input type="checkbox" class="switch" checked={prefs.menuOnFocus} onchange={(e) => setPref('menuOnFocus', e.currentTarget.checked)} /></label>
          <label class="field toggle"><span><b>{t('pref_offer')}</b><small>{t('pref_offer_hint')}</small></span><input type="checkbox" class="switch" checked={prefs.offerSave} onchange={(e) => setPref('offerSave', e.currentTarget.checked)} /></label>
          <label class="field toggle"><span><b>{t('pref_otp')}</b><small>{t('pref_otp_hint')}</small></span><input type="checkbox" class="switch" checked={prefs.autoOtp} onchange={(e) => setPref('autoOtp', e.currentTarget.checked)} /></label>
        </section>
        <h2>{t('never_sites')}</h2>
        {#if prefs.neverSites.length === 0}
          <p class="hint pad">{t('never_sites_empty')}</p>
        {:else}
          <section class="card">
            {#each prefs.neverSites as s (s)}
              <div class="field"><span class="val">{s}</span><button class="ghost small" onclick={() => setPref('neverSites', prefs.neverSites.filter((x) => x !== s))}>{t('remove')}</button></div>
            {/each}
          </section>
        {/if}
        <h2>{t('shortcuts')}</h2>
        <section class="card">
          <div class="field"><span><b>{t('fill_on_page')}</b></span><span class="keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>L</kbd></span></div>
        </section>
      {/if}
    </main>
    {/key}

    <nav class="tabs">
      <button class:active={tab === 'vault'} onclick={() => (tab = 'vault')}>{@render svg('vault')}{t('vault')}</button>
      <button class:active={tab === 'generator'} onclick={() => (tab = 'generator')}>{@render svg('regen')}{t('generator')}</button>
      <button class:active={tab === 'settings'} onclick={() => (tab = 'settings')}>{@render svg('sliders')}{t('settings')}</button>
    </nav>
   </div>
  {/if}
  {#if toast}<div class="toast" in:fly={{ y: 10, duration: ms(200), easing: cubicOut }} out:fade={{ duration: ms(150) }}>{toast}</div>{/if}
</div>

<style>
  /* окно Chrome на Linux прямоугольное: снаружи тёмная подложка с отступом, внутри скруглённое окно */
  :global(html),
  :global(body) {
    margin: 0;
    background: #0b0b0d;
    color: #ececef;
    font: 13px/1.45 Inter, system-ui, sans-serif;
  }
  :global(*) {
    box-sizing: border-box;
  }
  :global(::-webkit-scrollbar) {
    width: 10px;
    height: 0;
  }
  :global(::-webkit-scrollbar-track) {
    background: transparent;
  }
  :global(::-webkit-scrollbar-thumb) {
    background: #2c2d33;
    border-radius: 6px;
    border: 3px solid #141417;
  }
  :global(::-webkit-scrollbar-thumb:hover) {
    background: #3a3b42;
  }
  :global(::-webkit-scrollbar-button) {
    display: none;
  }
  :global(body) {
    padding: 6px;
  }
  /* панель на странице: рамку и скругление даёт контейнер на странице */
  :global(html.panel),
  :global(html.panel body) {
    background: #141417;
    padding: 0;
    overflow: hidden;
  }
  :global(html.panel) .app {
    width: 100%;
    height: 100vh;
    border: 0;
    border-radius: 0;
    box-shadow: none;
  }
  .app {
    width: 380px;
    height: 588px;
    display: flex;
    flex-direction: column;
    position: relative;
    overflow: hidden;
    border-radius: 14px;
    border: 1px solid #26262b;
    background: #141417;
    box-shadow: 0 0 0 1px #0006;
  }
  svg {
    width: 16px;
    height: 16px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
    flex: none;
  }

  /* шапка */
  .bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 12px 10px 14px;
    background: #18181b;
    border-bottom: 1px solid #26262b;
    min-height: 56px;
  }
  .title {
    flex: 1;
    font-weight: 600;
    font-size: 15px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .logo {
    flex: none;
    width: 28px;
    height: 28px;
    border-radius: 9px;
    background: linear-gradient(135deg, #2c2540, #222227);
    border: 1px solid #34303f;
    color: #b8a6ff;
    display: grid;
    place-items: center;
    font-weight: 700;
    font-size: 12px;
  }

  /* поиск и фильтры */
  .searchbar {
    display: flex;
    gap: 6px;
    padding: 10px 12px 4px;
    background: #141417;
  }
  .search {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 8px;
    height: 36px;
    padding: 0 12px;
    border-radius: 10px;
    border: 1px solid #2c2d33;
    background: #1b1b1f;
    color: #8e8e98;
    transition: border-color 0.12s;
  }
  .search:focus-within {
    border-color: #5d5f6a;
  }
  .search input {
    all: unset;
    flex: 1;
    color: #ececef;
    font-size: 13px;
  }
  .search input::placeholder {
    color: #8e8e98;
  }
  .fbtn {
    position: relative;
    width: 36px;
    height: 36px;
    border: 1px solid #2c2d33 !important;
    background: #1b1b1f !important;
    border-radius: 10px !important;
  }
  .fbtn:focus-visible {
    outline: none;
    border-color: #5d5f6a !important;
  }
  .fbtn svg {
    width: 16px;
    height: 16px;
  }
  .fbtn.on {
    border-color: #5d5f6a !important;
    color: #ececef !important;
  }
  .badge {
    position: absolute;
    top: -5px;
    right: -5px;
    min-width: 16px;
    height: 16px;
    border-radius: 8px;
    background: #7c5cff;
    color: #fff;
    font-size: 10px;
    display: grid;
    place-items: center;
    padding: 0 4px;
  }
  .filters {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 6px;
    padding: 6px 12px 2px;
    animation: down 0.16s cubic-bezier(0.22, 1, 0.36, 1);
  }
  .filters .ghost {
    grid-column: 1 / -1;
    justify-self: end;
  }
  @keyframes down {
    from {
      opacity: 0;
      transform: translateY(-4px);
    }
  }

  /* содержимое */
  .scroll {
    flex: 1;
    overflow-y: auto;
    padding: 2px 12px 16px;
  }
  h2 {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    color: #c9c9d1;
    margin: 14px 2px 7px;
  }
  .count {
    color: #8e8e98;
    font-weight: 500;
  }
  .card {
    border: 1px solid #28292e;
    border-radius: 12px;
    background: #1b1b1f;
  }
  .emptycard {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    font-size: 12px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 8px 8px 10px;
    min-height: 52px;
    cursor: pointer;
    outline: none;
    border-radius: 12px;
  }
  .item + .item,
  .field + .field {
    border-top: 1px solid #25252a;
  }
  /* меню «⋯» выходит за карточку, поэтому скругляем крайние строки, а не обрезаем */
  .card > .item {
    border-radius: 0;
  }
  .card > .item:first-child {
    border-radius: 11px 11px 0 0;
  }
  .card > .item:last-child {
    border-radius: 0 0 11px 11px;
  }
  .card > .item:only-child {
    border-radius: 11px;
  }
  .item:hover,
  .item:focus-visible {
    background: #222227;
  }
  .av {
    flex: none;
    width: 32px;
    height: 32px;
    border-radius: 9px;
    background: #222227;
    border: 1px solid #2c2d33;
    display: grid;
    place-items: center;
    font-weight: 600;
    font-size: 13px;
    color: #c9c9d1;
    overflow: hidden;
  }
  .av img {
    width: 18px;
    height: 18px;
  }
  .av svg {
    width: 15px;
    height: 15px;
    color: #a18bff;
  }
  .av.big {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    font-size: 17px;
  }
  .av.big img {
    width: 24px;
    height: 24px;
  }
  .who {
    flex: 1;
    min-width: 0;
  }
  .who b,
  .who small {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .who b {
    font-weight: 500;
  }
  small {
    color: #8e8e98;
    font-size: 11px;
  }
  .morewrap {
    position: relative;
  }
  .pop {
    position: absolute;
    right: 0;
    top: 30px;
    z-index: 10;
    width: 210px;
    padding: 4px;
    border-radius: 12px;
    background: #1f1f23;
    border: 1px solid #2c2d33;
    box-shadow: 0 14px 32px #000a;
  }
  .pop button {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    border: 0;
    background: transparent;
    padding: 7px 9px;
    border-radius: 8px;
    text-align: left;
    font-weight: 400;
    justify-content: flex-start;
  }
  .pop button svg {
    color: #8e8e98;
    width: 15px;
    height: 15px;
  }
  .pop button:hover {
    background: #2a2a30;
  }
  .item:last-child .pop {
    top: auto;
    bottom: 30px;
  }

  /* скелетоны */
  .sk {
    cursor: default;
  }
  .sk .av,
  .sk i {
    background: linear-gradient(90deg, #222227 0%, #2a2a30 50%, #222227 100%);
    background-size: 200% 100%;
    animation: shimmer 1.2s linear infinite;
    border: 0;
  }
  .sk i {
    display: block;
    height: 9px;
    width: 60%;
    border-radius: 5px;
    margin: 4px 0;
  }
  .sk i.short {
    width: 35%;
  }
  @keyframes shimmer {
    to {
      background-position: -200% 0;
    }
  }

  /* карточка записи */
  .hero {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 2px 4px;
  }
  .hero b {
    font-size: 16px;
    font-weight: 600;
  }
  .field {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 10px 10px 12px;
    min-height: 44px;
  }
  .field > span:first-child {
    flex: 1;
    min-width: 0;
  }
  .field small {
    display: block;
  }
  .field b {
    font-weight: 500;
    display: block;
  }
  .val {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .mono {
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }
  .code {
    font-size: 18px;
    letter-spacing: 1px;
  }
  /* регистрируем --p, чтобы кольцо 2FA убывало плавно, а не рывком раз в секунду */
  @property --p {
    syntax: '<percentage>';
    inherits: false;
    initial-value: 100%;
  }
  .ring {
    transition: --p 1s linear;
    flex: none;
    width: 26px;
    height: 26px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font-size: 10px;
    color: #8e8e98;
    background:
      radial-gradient(closest-side, #1b1b1f 78%, transparent 80%),
      conic-gradient(#7c5cff var(--p), #2c2d33 0);
  }
  .ring.urgent {
    color: #ff8a8f;
    background:
      radial-gradient(closest-side, #1b1b1f 78%, transparent 80%),
      conic-gradient(#e5484d var(--p), #2c2d33 0);
  }
  .actions {
    display: flex;
    gap: 8px;
    padding: 10px 12px;
    border-top: 1px solid #26262b;
    background: #18181b;
  }

  /* форма */
  .form .input {
    display: block;
    padding: 8px 12px 9px;
  }
  .form .input + .input {
    border-top: 1px solid #25252a;
  }
  .form input {
    all: unset;
    display: block;
    width: 100%;
    padding-top: 2px;
    color: #ececef;
  }
  .form input::placeholder {
    color: #5f5f68;
  }
  .with {
    display: flex;
    align-items: center;
    gap: 2px;
  }
  .with input {
    flex: 1;
  }

  /* пустые состояния */
  .empty {
    display: grid;
    gap: 8px;
    justify-items: center;
    text-align: center;
    padding: 80px 28px 0;
  }
  .empty p {
    margin: 0;
  }
  .big {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    background: #1b1b1f;
    border: 1px solid #2c2d33;
    color: #a18bff;
    display: grid;
    place-items: center;
    font-weight: 700;
    font-size: 17px;
    margin-bottom: 4px;
  }
  .big svg {
    width: 20px;
    height: 20px;
  }
  .hint {
    color: #8e8e98;
    font-size: 12px;
    margin: 6px 2px;
  }
  .pad {
    padding: 10px 12px;
    margin: 0;
  }
  .muted {
    color: #8e8e98;
  }
  .err {
    color: #ff8a8f;
    font-size: 12px;
  }

  /* генератор */
  .gen {
    margin-top: 12px;
  }
  .pw {
    padding: 16px 14px 10px;
    font-size: 17px;
    line-height: 1.5;
    overflow-wrap: anywhere;
    min-height: 52px;
  }
  .pw .d {
    color: #8fb0ff;
  }
  .pw .s {
    color: #c2b4ff;
  }
  .meter {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 0 14px 12px;
  }
  .meter i {
    width: 28px;
    height: 4px;
    border-radius: 2px;
    background: #2c2d33;
  }
  .meter i.on[data-l='1'] {
    background: #e5484d;
  }
  .meter i.on[data-l='2'] {
    background: #d6a23a;
  }
  .meter i.on[data-l='3'],
  .meter i.on[data-l='4'] {
    background: #2f9e6e;
  }
  .meter span {
    margin-left: 6px;
    font-size: 11px;
    color: #8e8e98;
  }
  .hidden {
    visibility: hidden;
  }
  .seg {
    display: flex;
    gap: 2px;
    padding: 3px;
    margin: 12px 0 8px;
    border: 1px solid #28292e;
    border-radius: 11px;
    background: #1b1b1f;
  }
  .seg button,
  .chips button {
    flex: 1;
    border-color: transparent;
    background: transparent;
    color: #8e8e98;
  }
  .seg button.active,
  .chips button.active {
    background: #2c2d33;
    border-color: #34353c;
    color: #ececef;
  }
  .chips {
    display: flex;
    gap: 4px;
  }
  .chips button {
    flex: none;
    min-width: 34px;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }
  .range input {
    flex: 1;
    accent-color: #7c5cff;
    min-width: 0;
  }
  .range > span:first-child {
    flex: none !important;
    width: 52px;
  }
  .step {
    width: 26px;
    height: 26px;
    padding: 0 !important;
    font-size: 15px;
    border-radius: 8px !important;
  }
  .sets {
    display: grid !important;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
    width: 100%;
  }
  .set {
    height: 34px;
    border-radius: 10px;
    background: #1f1f23;
    border-color: #2c2d33;
    color: #8e8e98;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 12px;
  }
  .set.on {
    background: #2a2440;
    border-color: #5b4bb0;
    color: #ececef;
  }
  .set.on svg {
    width: 12px;
    height: 12px;
    color: #b8a6ff;
    stroke-width: 2.4;
  }
  .set:disabled {
    opacity: 1;
    cursor: not-allowed;
  }
  .num {
    width: 26px;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .keys {
    display: flex;
    gap: 3px;
  }
  .foot {
    display: flex;
    gap: 6px;
    align-items: center;
    padding: 8px 10px;
    border-top: 1px solid #26262b;
    background: #18181b;
    border-radius: 0 0 12px 12px;
  }
  .sp {
    flex: 1;
  }
  .offer {
    margin-top: 12px;
  }

  /* кнопки */
  button {
    font: 500 12px Inter, system-ui, sans-serif;
    color: #ececef;
    background: #222227;
    border: 1px solid #2c2d33;
    border-radius: 9px;
    padding: 6px 12px;
    cursor: pointer;
    white-space: nowrap;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    transition: background 0.12s, border-color 0.12s, transform 0.08s;
  }
  button:hover {
    background: #2a2a30;
  }
  button svg {
    width: 14px;
    height: 14px;
  }
  button.primary {
    background: #7c5cff;
    border-color: #7c5cff;
    color: #fff;
  }
  button.primary:hover {
    background: #8a6dff;
  }
  button.outline {
    background: transparent;
    border-color: #34353c;
  }
  button.outline:hover {
    background: #26272d;
  }
  button.small {
    padding: 4px 10px;
    border-radius: 8px;
  }
  button.wide,
  button.grow {
    flex: 1;
    padding: 9px;
  }
  button.ghost {
    background: transparent;
    border-color: transparent;
    color: #8e8e98;
  }
  button.ghost:hover {
    background: #222227;
    color: #ececef;
  }
  button.icon {
    background: transparent;
    border-color: transparent;
    color: #8e8e98;
    padding: 6px;
  }
  button.icon:hover {
    background: #26272d;
    color: #ececef;
  }
  button.icon svg {
    width: 16px;
    height: 16px;
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  button:focus-visible,
  .switch:focus-visible {
    outline: 2px solid #5d5f6a;
    outline-offset: 1px;
  }
  .switch {
    appearance: none;
    flex: none;
    width: 32px;
    height: 19px;
    border-radius: 10px;
    background: #303036;
    position: relative;
    cursor: pointer;
    transition: background 0.15s;
    margin: 0;
  }
  .switch::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 15px;
    height: 15px;
    border-radius: 50%;
    background: #fff;
    transition: transform 0.18s cubic-bezier(0.22, 1, 0.36, 1);
  }
  .switch:checked {
    background: #7c5cff;
  }
  .switch:checked::after {
    transform: translateX(13px);
  }
  label.toggle {
    cursor: pointer;
  }

  /* нижние вкладки */
  .tabs {
    display: flex;
    gap: 4px;
    padding: 6px;
    border-top: 1px solid #26262b;
    background: #18181b;
  }
  .tabs button {
    flex: 1;
    display: grid;
    justify-items: center;
    gap: 3px;
    padding: 7px 0 6px;
    border: 0;
    border-radius: 11px;
    background: transparent;
    color: #8e8e98;
    font-size: 11px;
    outline: none;
  }
  .tabs button svg {
    width: 18px;
    height: 18px;
  }
  .tabs button:hover {
    color: #ececef;
    background: #1f1f23;
  }
  .tabs button.active {
    color: #ececef;
    background: #26272d;
  }
  .tabs button.active svg {
    color: #a18bff;
  }
  .tabs button:focus-visible {
    box-shadow: inset 0 0 0 1px #5d5f6a;
  }
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .ok {
    display: grid;
    place-items: center;
    color: #5fd4a0;
  }
  .ok svg {
    width: 16px;
    height: 16px;
    stroke-width: 2.4;
  }
  button:active:not(:disabled) {
    transform: scale(0.97);
  }
  .pop {
    transform-origin: top right;
  }
  .item:last-child .pop {
    transform-origin: bottom right;
  }
  .meter i {
    transition: background 0.3s ease;
  }
  @media (prefers-reduced-motion: reduce) {
    :global(*) {
      animation-duration: 0s !important;
      transition-duration: 0s !important;
    }
  }
  .toast {
    position: absolute;
    left: 12px;
    right: 12px;
    bottom: 70px;
    padding: 10px 12px;
    border-radius: 11px;
    background: #26272d;
    border: 1px solid #34353c;
    box-shadow: 0 10px 28px #000a;
    font-size: 12px;
    animation: up 0.16s cubic-bezier(0.22, 1, 0.36, 1);
    z-index: 20;
  }
  @keyframes up {
    from {
      opacity: 0;
      transform: translateY(4px);
    }
  }
  kbd {
    font: 10px Inter, system-ui, sans-serif;
    padding: 2px 5px;
    border-radius: 5px;
    border: 1px solid #2c2d33;
    background: #222227;
    color: #ececef;
  }
</style>
