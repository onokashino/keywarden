// Keywarden site: launcher demo, tabs, reveal on scroll, copy buttons, docs scrollspy.
(() => {
  const ru = document.documentElement.lang === 'ru';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const T = ru
    ? {
        pass: 'Пароль скопирован, очистится через 30 с',
        user: 'Логин скопирован',
        otp: 'Код 2FA скопирован',
        noOtp: 'У этой записи нет 2FA',
        ssh: 'Открываю терминал: ssh deploy@prod.example.com',
        empty: 'Ничего не найдено',
        copied: 'Скопировано',
        copy: 'Копировать',
        enter: { pass: 'пароль', ssh: 'подключиться' },
        card: 'Карта',
        key: 'Ключ SSH',
      }
    : {
        pass: 'Password copied, clears in 30 s',
        user: 'Username copied',
        otp: '2FA code copied',
        noOtp: 'This entry has no 2FA',
        ssh: 'Opening a terminal: ssh deploy@prod.example.com',
        empty: 'Nothing found',
        copied: 'Copied',
        copy: 'Copy',
        enter: { pass: 'password', ssh: 'connect' },
        card: 'Card',
        key: 'SSH key',
      };

  // remember an explicit language choice so the root page stops redirecting
  document.querySelectorAll('[data-lang]').forEach((a) =>
    a.addEventListener('click', () => {
      try { localStorage.setItem('kw-lang', a.dataset.lang); } catch {}
    }),
  );

  // --- nav gets denser once the page scrolls ---
  const nav = document.querySelector('.nav');
  const onScroll = () => nav && nav.classList.toggle('scrolled', scrollY > 8);
  addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  // --- section menu on narrow screens ---
  const menuBtn = document.getElementById('menuBtn');
  if (nav && menuBtn) {
    const setOpen = (on) => { nav.classList.toggle('open', on); menuBtn.setAttribute('aria-expanded', on); };
    menuBtn.addEventListener('click', () => setOpen(!nav.classList.contains('open')));
    document.querySelectorAll('#navLinks a').forEach((a) => a.addEventListener('click', () => setOpen(false)));
    addEventListener('keydown', (e) => { if (e.key === 'Escape') setOpen(false); });
  }

  // --- reveal on scroll (only when JS runs: html.js hides .reveal until seen) ---
  const reveals = document.querySelectorAll('.reveal');
  if (reduced || !('IntersectionObserver' in window)) {
    reveals.forEach((el) => el.classList.add('in'));
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting) continue;
          e.target.classList.add('in');
          io.unobserve(e.target);
        }
      },
      { rootMargin: '0px 0px -8% 0px', threshold: 0.12 },
    );
    // siblings in a grid come in one after another
    reveals.forEach((el) => {
      const peers = el.parentElement ? [...el.parentElement.children].filter((c) => c.classList.contains('reveal')) : [];
      const i = peers.indexOf(el);
      if (peers.length > 1 && i > 0) el.style.setProperty('--d', `${Math.min(i, 8) * 60}ms`);
      io.observe(el);
    });
  }

  // --- soft spotlight that follows the cursor on cards ---
  document.querySelectorAll('.card, .node').forEach((c) =>
    c.addEventListener('pointermove', (e) => {
      const r = c.getBoundingClientRect();
      c.style.setProperty('--mx', `${e.clientX - r.left}px`);
      c.style.setProperty('--my', `${e.clientY - r.top}px`);
    }),
  );

  // --- tabs: gallery and OS switchers (role=tablist), with a sliding indicator ---
  document.querySelectorAll('[role="tablist"]').forEach((list) => {
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    const ind = document.createElement('span');
    ind.className = 'tab-ind';
    ind.setAttribute('aria-hidden', 'true');
    list.prepend(ind);
    const place = (tab, animate) => {
      ind.style.transition = animate ? '' : 'none';
      ind.style.width = `${tab.offsetWidth}px`;
      ind.style.height = `${tab.offsetHeight}px`;
      ind.style.transform = `translate(${tab.offsetLeft}px, ${tab.offsetTop}px)`;
    };
    const img = list.dataset.img && document.getElementById(list.dataset.img);
    const select = (tab, focus) => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute('aria-selected', on);
        t.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      });
      place(tab, true);
      if (img && tab.dataset.src) swapImage(img, tab.dataset.src, tab.dataset.alt || tab.textContent);
      if (list.dataset.cap) {
        const cap = document.getElementById(list.dataset.cap);
        cap.classList.remove('show');
        void cap.offsetWidth;
        cap.textContent = tab.dataset.cap || '';
        cap.classList.add('show');
      }
      if (focus) tab.focus();
    };
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => select(t));
      t.addEventListener('keydown', (e) => {
        const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
        if (d) select(tabs[(i + d + tabs.length) % tabs.length], true);
      });
    });
    const current = () => tabs.find((t) => t.getAttribute('aria-selected') === 'true') || tabs[0];
    requestAnimationFrame(() => place(current(), false));
    addEventListener('resize', () => place(current(), false));
    // hidden panels (docs OS tabs) measure as zero until shown
    new ResizeObserver(() => place(current(), false)).observe(list);
    tabs.forEach((t) => t.dataset.src && (new Image().src = t.dataset.src));
  });

  // crossfade: the new screenshot fades in over the old one, no flash of empty frame
  function swapImage(img, src, alt) {
    if (img.getAttribute('src') === src) return;
    const frame = img.parentElement;
    const next = img.cloneNode();
    next.removeAttribute('id');
    next.src = src;
    next.alt = alt;
    next.className = 'shot-next';
    const done = () => {
      frame.appendChild(next);
      requestAnimationFrame(() => next.classList.add('in'));
      setTimeout(() => {
        img.src = src;
        img.alt = alt;
        next.remove();
      }, reduced ? 0 : 320);
    };
    next.decode ? next.decode().then(done, done) : done();
  }

  // --- copy buttons on code blocks ---
  document.querySelectorAll('pre').forEach((pre) => {
    const b = document.createElement('button');
    b.className = 'copy';
    b.type = 'button';
    b.textContent = T.copy;
    b.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(pre.querySelector('code')?.innerText ?? pre.innerText);
        b.textContent = T.copied;
        setTimeout(() => (b.textContent = T.copy), 1400);
      } catch {}
    });
    pre.appendChild(b);
  });

  // --- docs: highlight the section being read: the last heading above the reading line ---
  const side = document.querySelector('.side');
  if (side) {
    const links = [...side.querySelectorAll('a[href^="#"]')];
    const heads = links.map((a) => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
    let current;
    const spy = () => {
      const line = 140;
      let i = 0;
      heads.forEach((h, k) => { if (h.getBoundingClientRect().top <= line) i = k; });
      // в самом низу страницы последний раздел может так и не дойти до линии
      if (innerHeight + scrollY >= document.documentElement.scrollHeight - 4) i = heads.length - 1;
      const a = links.find((l) => l.getAttribute('href') === `#${heads[i]?.id}`);
      if (a === current) return;
      current?.classList.remove('active');
      a?.classList.add('active');
      current = a;
      a?.scrollIntoView({ block: 'nearest' });
    };
    addEventListener('scroll', spy, { passive: true });
    spy();
  }

  // --- launcher demo ---
  const demo = document.querySelector('.launcher');
  if (!demo) return;
  const input = demo.querySelector('input');
  const list = demo.querySelector('.l-list');
  const toast = document.getElementById('toast');
  const who = ru ? 'anna.petrova' : 'alex.morgan';
  const mail = `${who}@proton.me`;
  const entries = [
    { id: 'gh', t: 'GitHub', s: [who, 'github.com'], c: '#24292f', l: 'GH', otp: true, g: ru ? 'Работа' : 'Work' },
    { id: 'go', t: 'Google', s: [`${who}@gmail.com`, 'accounts.google.com'], c: '#1a73e8', l: 'G', otp: true },
    { id: 'pm', t: 'Proton Mail', s: [mail, 'proton.me'], c: '#6d4aff', l: 'P', otp: true },
    { id: 'dk', t: ru ? 'Ключ деплоя prod' : 'prod deploy key', s: ['deploy@prod', 'prod.example.com'], c: '#334155', l: '>_', tag: T.key, ssh: true },
    { id: 'rv', t: 'Revolut', s: ['+44 7700 900123', 'app.revolut.com'], c: '#0b0b0f', l: 'R', otp: true },
    { id: 'vi', t: 'Visa', s: [ru ? 'ANNA PETROVA' : 'ALEX MORGAN', '•••• 4242'], c: '#1a1f71', l: 'V', tag: T.card },
    { id: 'hz', t: 'Hetzner Cloud', s: [`admin@${who}.dev`, 'console.hetzner.cloud'], c: '#d50c2d', l: 'H', otp: true },
    { id: 'wf', t: ru ? 'Домашний Wi-Fi' : 'Home Wi-Fi', s: ['keenetic-5G', '192.168.1.1'], c: '#0e7490', l: 'W' },
    { id: 'fi', t: 'Figma', s: [mail, 'figma.com'], c: '#a259ff', l: 'F' },
    { id: 'sl', t: 'Slack', s: [mail, 'app.slack.com'], c: '#4a154b', l: 'S' },
  ];
  const MAX = 6;
  let shown = [];
  let sel = 0;
  let toastTimer;
  const rows = new Map(); // id -> <li>, kept between renders so rows can glide instead of blinking
  const hl = document.createElement('div');
  hl.className = 'l-hl';
  list.appendChild(hl);
  const empty = document.createElement('li');
  empty.className = 'l-empty';
  empty.textContent = T.empty;

  // fake 6-digit codes that change every 30 s, like the real thing
  const code = (id) => {
    const w = Math.floor(Date.now() / 30000);
    const seed = [...id].reduce((a, c) => a + c.charCodeAt(0), 0);
    const n = Math.abs(Math.sin((w + 1) * (seed + 3) * 12.9898) * 43758.5453) % 1;
    const s = String(Math.floor(n * 1e6)).padStart(6, '0');
    return `${s.slice(0, 3)} ${s.slice(3)}`;
  };
  const left = () => 1 - (Date.now() % 30000) / 30000;

  const makeRow = (e) => {
    const li = document.createElement('li');
    li.className = 'l-row';
    li.setAttribute('role', 'option');
    li.innerHTML = `<span class="l-ico" style="background:${e.c}">${e.l}</span>
      <span class="l-main"><span class="l-title"></span><span class="l-sub"></span></span>
      <span class="l-right">${
        e.otp
          ? `<span class="l-otp"><span class="l-code"></span><span class="l-bar"><i></i></span></span>`
          : e.tag
            ? `<span class="l-tag">${e.tag}</span>`
            : ''
      }<span class="l-enter"><kbd>Enter</kbd>${e.ssh ? T.enter.ssh : T.enter.pass}</span></span>`;
    li.querySelector('.l-title').textContent = e.t;
    li.querySelector('.l-sub').textContent = e.s.join(' · ');
    li.addEventListener('mousemove', () => {
      const k = shown.findIndex((x) => x.id === e.id);
      if (k >= 0 && k !== sel) { sel = k; paintSelection(); }
    });
    li.addEventListener('click', () => {
      sel = shown.findIndex((x) => x.id === e.id);
      paintSelection();
      act('pass');
    });
    return li;
  };

  const tick = () => {
    const w = `${left() * 100}%`;
    rows.forEach((li, id) => {
      const c = li.querySelector('.l-code');
      if (!c) return;
      c.textContent = code(id);
      li.querySelector('.l-bar i').style.width = w;
    });
  };

  const paintSelection = () => {
    shown.forEach((e, k) => rows.get(e.id)?.setAttribute('aria-selected', k === sel));
    const li = shown[sel] && rows.get(shown[sel].id);
    hl.style.opacity = li ? '1' : '0';
    if (li) {
      hl.style.height = `${li.offsetHeight}px`;
      hl.style.transform = `translateY(${li.offsetTop}px)`;
    }
  };

  // FLIP: remember where rows were, rebuild the order, then glide each row from old to new place
  const render = () => {
    const q = input.value.trim().toLowerCase();
    const next = entries.filter((e) => !q || [e.t, ...e.s].some((f) => f.toLowerCase().includes(q))).slice(0, MAX);
    const before = new Map([...rows].map(([id, li]) => [id, li.offsetTop]));
    shown = next;
    if (sel >= shown.length) sel = 0;
    const keep = new Set(shown.map((e) => e.id));
    rows.forEach((li, id) => {
      if (!keep.has(id)) { li.remove(); rows.delete(id); }
    });
    shown.forEach((e) => {
      let li = rows.get(e.id);
      if (!li) { li = makeRow(e); rows.set(e.id, li); li.classList.add('l-new'); }
      list.appendChild(li);
    });
    if (!shown.length) list.appendChild(empty); else empty.remove();
    tick();
    if (!reduced) {
      shown.forEach((e, k) => {
        const li = rows.get(e.id);
        const was = before.get(e.id);
        if (li.classList.contains('l-new')) {
          li.style.setProperty('--d', `${k * 22}ms`);
          requestAnimationFrame(() => li.classList.remove('l-new'));
        } else if (was !== undefined && was !== li.offsetTop) {
          li.style.transition = 'none';
          li.style.transform = `translateY(${was - li.offsetTop}px)`;
          requestAnimationFrame(() => {
            li.style.transition = '';
            li.style.transform = '';
          });
        }
      });
    } else {
      rows.forEach((li) => li.classList.remove('l-new'));
    }
    paintSelection();
  };

  const say = (msg) => {
    toast.lastElementChild.textContent = msg;
    toast.classList.remove('show');
    void toast.offsetWidth;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 1900);
  };
  const act = (what) => {
    const e = shown[sel];
    if (!e) return;
    const li = rows.get(e.id);
    li?.classList.remove('l-press');
    void li?.offsetWidth;
    li?.classList.add('l-press');
    if (what === 'pass' && e.ssh) return say(T.ssh);
    if (what === 'otp' && !e.otp) return say(T.noOtp);
    say(T[what]);
  };

  input.addEventListener('input', () => { sel = 0; render(); });
  input.addEventListener('keydown', (e) => {
    const k = e.key.toLowerCase();
    if (e.key === 'ArrowDown' || (e.ctrlKey && k === 'j')) sel = Math.min(sel + 1, shown.length - 1);
    else if (e.key === 'ArrowUp' || (e.ctrlKey && k === 'k')) sel = Math.max(sel - 1, 0);
    else if (e.key === 'Enter') act('pass');
    else if (e.ctrlKey && k === 'u') act('user');
    else if (e.ctrlKey && k === 't') act('otp');
    else if (e.key === 'Escape') { input.value = ''; sel = 0; render(); }
    else return;
    e.preventDefault();
    paintSelection();
  });
  setInterval(tick, 1000);
  render();
  addEventListener('resize', paintSelection);

  // autoplay until the visitor touches the demo
  let touched = false;
  const stop = () => {
    touched = true;
    demo.classList.remove('autoplay');
  };
  ['pointerdown', 'keydown', 'focusin'].forEach((ev) => demo.addEventListener(ev, stop));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const type = async (s) => {
    for (const ch of s) {
      if (touched) return false;
      input.value += ch;
      sel = 0;
      render();
      await sleep(95 + Math.random() * 70);
    }
    return !touched;
  };
  const script = [
    ['git', 'pass', 0],
    ['prod', 'pass', 0],
    ['hetz', 'otp', 0],
    ['proton', 'user', 0],
  ];
  const play = async () => {
    demo.classList.add('autoplay');
    for (let n = 0; n < 3 && !touched; n++) {
      for (const [q, what] of script) {
        if (!(await type(q))) return;
        await sleep(700);
        if (touched) return;
        act(what);
        await sleep(1700);
        if (touched) return;
        input.value = '';
        render();
        await sleep(600);
      }
    }
    demo.classList.remove('autoplay');
  };
  if (!reduced) {
    const io = new IntersectionObserver((es) => {
      if (es.some((e) => e.isIntersecting)) {
        io.disconnect();
        setTimeout(play, 900);
      }
    });
    io.observe(demo);
  }
})();
