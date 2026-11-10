// Главная Keywarden: демо лаунчера, вкладки на клавишах, печать команд, появление разделов.
// Всё содержимое есть в HTML; без этого файла страница просто стоит на месте.
(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  // --- шапка плотнеет после прокрутки, пункт текущего раздела подсвечен ---
  const nav = $('#nav');
  const onScroll = () => nav.classList.toggle('scrolled', scrollY > 8);
  addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  const links = $$('.nav-links a');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (!e.isIntersecting) return;
      links.forEach(a => a.setAttribute('aria-current', a.hash === '#' + e.target.id));
    }), { rootMargin: '-45% 0px -50% 0px' });
    // следим за всеми разделами: на разделе без пункта в меню подсветка гаснет
    $$('main > section').forEach(s => io.observe(s));
  }

  // --- заголовок первого экрана: слова поднимаются по очереди ---
  const h1 = $('.hero h1');
  if (h1 && !reduced) {
    let i = 0;
    const walk = node => {
      [...node.childNodes].forEach(n => {
        if (n.nodeType === 3) {
          const frag = document.createDocumentFragment();
          n.textContent.split(/(\s+)/).forEach(part => {
            if (!part) return;
            if (/^\s+$/.test(part)) { frag.append(part); return; }
            const w = document.createElement('span');
            w.className = 'w'; w.style.setProperty('--i', i++); w.textContent = part;
            frag.append(w);
          });
          n.replaceWith(frag);
        } else if (n.nodeType === 1) walk(n);
      });
    };
    walk(h1);
  }

  // --- демо лаунчера: Shift+P (Super браузеру не достаётся), затем Enter ---
  const rig = $('#rig'), screen = $('#screen');
  if (rig && screen) {
    const keys = $$('.key', rig);
    const tpl = id => $('#' + id).innerHTML;
    let stage = 0, timer = 0, auto = [], touched = false;
    const press = (k, on) => keys.filter(e => e.dataset.k.toLowerCase() === k.toLowerCase()).forEach(e => e.classList.toggle('down', on));
    const tap = (k, ms = 160) => { press(k, true); setTimeout(() => press(k, false), ms); };
    const launcher = () => { stage = 1; clearInterval(timer); screen.innerHTML = tpl('t-launch'); };
    const copied = () => {
      stage = 0; clearInterval(timer);
      screen.innerHTML = tpl('t-copied');
      let left = 30;
      const n = $('[data-left]', screen), bar = $('.bar i', screen);
      timer = setInterval(() => {
        left--;
        if (left <= 0) { clearInterval(timer); screen.innerHTML = tpl('t-cleared'); return; }
        n.textContent = left; bar.style.transform = 'scaleX(' + left / 30 + ')';
      }, 1000);
    };
    const stopAuto = () => { touched = true; auto.forEach(clearTimeout); auto = []; };
    keys.forEach(k => k.addEventListener('click', () => {
      stopAuto(); tap(k.dataset.k);
      if (k.dataset.k === 'P' || k.dataset.k === 'Meta' || k.dataset.k === 'Shift') launcher();
      else if (k.dataset.k === 'Enter' && stage === 1) copied();
    }));
    addEventListener('keydown', e => {
      if (e.target.closest('input, textarea, select, [contenteditable]')) return;
      if (e.key.toLowerCase() === 'p' && e.shiftKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault(); stopAuto(); press('Shift', true); press('P', true); launcher();
      } else if (e.key === 'Enter' && stage === 1 && !e.target.closest('a, button, summary')) {
        stopAuto(); press('Enter', true); copied();
      }
    });
    addEventListener('keyup', e => { press(e.key, false); if (!e.shiftKey) press('Shift', false); });
    // один раз показать сочетание самим, пока человек читает заголовок
    if (!reduced) {
      const at = (ms, f) => auto.push(setTimeout(() => !touched && f(), ms));
      at(1500, () => { press('Meta', true); });
      at(1650, () => { press('Shift', true); });
      at(1800, () => { press('P', true); });
      at(2050, () => { press('Meta', false); press('Shift', false); press('P', false); launcher(); });
      at(3300, () => { press('Enter', true); });
      at(3460, () => { press('Enter', false); copied(); });
    }
  }

  // --- вкладки на клавишах: обзор (цифры 1-6) и выбор системы ---
  const typeIn = panel => {
    if (reduced) return;
    $$('[data-type]', panel).forEach((el, j) => {
      const full = el.dataset.full || (el.dataset.full = el.textContent);
      el.textContent = '';
      let n = 0;
      setTimeout(function step() {
        el.textContent = full.slice(0, ++n);
        if (n < full.length) setTimeout(step, 22 + Math.random() * 30);
      }, 180 + j * 520);
    });
  };
  const tabsets = {};
  $$('[data-tabs]').forEach(list => {
    const tabs = $$('[role="tab"]', list);
    const panels = tabs.map(t => document.getElementById(t.getAttribute('aria-controls')));
    const select = (i, focus) => {
      tabs.forEach((t, j) => { t.setAttribute('aria-selected', j === i); t.tabIndex = j === i ? 0 : -1; });
      panels.forEach((p, j) => {
        p.hidden = j !== i;
        if (j === i && !reduced) { p.classList.remove('enter'); void p.offsetWidth; p.classList.add('enter'); }
      });
      if (focus) tabs[i].focus();
      if (list.dataset.tabs === 'os') typeIn(panels[i]);
    };
    tabs.forEach((t, i) => {
      t.id = t.id || list.dataset.tabs + '-tab-' + i;
      panels[i].setAttribute('aria-labelledby', t.id);
      t.addEventListener('click', () => select(i));
      t.addEventListener('keydown', e => {
        const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
        if (d) { e.preventDefault(); select((i + d + tabs.length) % tabs.length, true); }
      });
    });
    tabsets[list.dataset.tabs] = { select, tabs };
  });
  if (tabsets.tour) tabsets.tour.select(0);
  if (tabsets.os) {
    const ua = navigator.userAgent;
    const want = /Windows/.test(ua) ? 'windows' : /Mac/.test(ua) ? 'macos' : 'linux';
    tabsets.os.select(Math.max(0, tabsets.os.tabs.findIndex(t => t.dataset.os === want)));
  }
  addEventListener('keydown', e => {
    if (!tabsets.tour || e.ctrlKey || e.altKey || e.metaKey) return;
    if (e.target.closest('input, textarea, select, [contenteditable]')) return;
    if (/^[1-6]$/.test(e.key)) {
      const tour = $('#tour').getBoundingClientRect();
      // цифры работают, когда раздел на экране
      if (tour.top < innerHeight * 0.8 && tour.bottom > innerHeight * 0.2) tabsets.tour.select(+e.key - 1);
    }
  });

  // --- сравнение: клавиши выбирают соперника ---
  const rivals = $('[data-rivals]'), duel = $('#duel');
  if (rivals && duel) {
    const tabs = $$('[role="tab"]', rivals);
    const pick = (i, focus) => {
      const id = tabs[i].dataset.rival;
      tabs.forEach((t, j) => { t.setAttribute('aria-selected', j === i); t.tabIndex = j === i ? 0 : -1; });
      $$('#compare .rival').forEach(el => el.classList.toggle('on', el.dataset.for === id));
      if (!reduced) { duel.classList.remove('swap'); void duel.offsetWidth; duel.classList.add('swap'); }
      if (focus) tabs[i].focus();
    };
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => pick(i));
      t.addEventListener('keydown', e => {
        const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
        if (d) { e.preventDefault(); pick((i + d + tabs.length) % tabs.length, true); }
      });
    });
    pick(0);
  }

  // --- вопросы: на широком экране ответ на «экране» справа, стрелки ходят по списку ---
  const faqScreen = $('#faqScreen'), wide = matchMedia('(min-width: 961px)');
  if (faqScreen) {
    const items = $$('.faq-list details');
    const question = d => [...$('summary', d).childNodes].filter(n => !(n.classList && n.classList.contains('n'))).map(n => n.textContent).join('').trim();
    const show = i => {
      items.forEach((d, j) => d.classList.toggle('active', j === i));
      const pr = document.createElement('div');
      pr.className = 'prompt';
      const b = document.createElement('b');
      b.textContent = faqScreen.dataset.of.replace('{n}', i + 1).replace('{t}', items.length);
      pr.append('› ', b);
      const h = document.createElement('h3');
      h.textContent = question(items[i]);
      faqScreen.replaceChildren(pr, h, $('p', items[i]).cloneNode(true));
      if (!reduced) { faqScreen.classList.toggle('swap', false); void faqScreen.offsetWidth; faqScreen.classList.add('swap'); }
    };
    items.forEach((d, i) => {
      const sum = $('summary', d);
      sum.addEventListener('click', e => { if (wide.matches) { e.preventDefault(); show(i); } });
      sum.addEventListener('keydown', e => {
        const k = { ArrowDown: 1, ArrowUp: -1 }[e.key];
        if (!k || !wide.matches) return;
        e.preventDefault();
        const n = (i + k + items.length) % items.length;
        $('summary', items[n]).focus();
        show(n);
      });
    });
    show(0);
  }

  // --- меню разделов на телефоне ---
  const menuBtn = $('#menuBtn');
  if (menuBtn) {
    const setOpen = on => { nav.classList.toggle('open', on); menuBtn.setAttribute('aria-expanded', on); };
    menuBtn.addEventListener('click', () => setOpen(!nav.classList.contains('open')));
    $$('#navLinks a').forEach(a => a.addEventListener('click', () => setOpen(false)));
    addEventListener('keydown', e => { if (e.key === 'Escape') setOpen(false); });
  }

  // --- появление разделов ниже первого экрана ---
  if (!reduced && 'IntersectionObserver' in window) {
    const below = $$('main > section').filter(s => s.getBoundingClientRect().top > innerHeight);
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (!e.isIntersecting) return;
      e.target.classList.remove('pre');
      io.unobserve(e.target);
      if (e.target.id === 'install') { const open = $('.os-panel:not([hidden])'); if (open) typeIn(open); }
    }), { rootMargin: '0px 0px -18% 0px' });
    below.forEach(s => { s.classList.add('pre'); io.observe(s); });
  }
})();
