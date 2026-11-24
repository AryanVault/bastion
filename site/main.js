// Bastion landing page: progressive enhancement only. Every section is complete without this
// script; it adds the hero demo loop, scroll reveals, counters, filters and copy buttons.
(() => {
  "use strict";

  const motion = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const canHover = window.matchMedia("(hover: hover)").matches;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const belowFold = (el) => el.getBoundingClientRect().top > window.innerHeight * 0.9;

  /** Calls `fn(el)` once, the first time `el` scrolls into view. */
  function onceVisible(el, fn, threshold = 0.25) {
    if (!("IntersectionObserver" in window)) { fn(el); return; }
    const io = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) { io.unobserve(entry.target); fn(entry.target); }
      }
    }, { threshold });
    io.observe(el);
  }

  /* ------------------------------------------------------------ nav */
  const nav = $(".nav");
  const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 8);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  if ("IntersectionObserver" in window) {
    const links = new Map($$(".nav nav a").map((a) => [a.getAttribute("href").slice(1), a]));
    const spy = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        const link = links.get(entry.target.id);
        if (link && entry.isIntersecting) {
          links.forEach((a) => a.classList.remove("active"));
          link.classList.add("active");
        }
      }
    }, { rootMargin: "-45% 0px -50% 0px" });
    links.forEach((_, id) => { const s = document.getElementById(id); if (s) spy.observe(s); });
  }

  /* ------------------------------------------------------------ scroll reveals */
  if (motion) {
    const groups = [".sec-head", ".asks", ".compare-wrap", ".fit", ".steps", ".hidden-demo",
      ".filters", ".pipe", ".built", ".term", ".legend", ".more", ".final-in"];
    for (const sel of groups) {
      for (const group of $$(sel)) {
        if (!belowFold(group)) continue;
        const kids = group.matches(".asks, .built, .fit") ? Array.from(group.children) : [group];
        kids.forEach((kid, i) => {
          kid.classList.add("rv");
          kid.style.setProperty("--d", `${Math.min(i, 6) * 80}ms`);
          onceVisible(kid, (el) => el.classList.add("in"), 0.12);
        });
      }
    }
  }

  /* ------------------------------------------------------------ counters */
  function countUp(el) {
    const to = Number(el.dataset.to);
    if (!motion || to === 0) return;
    const start = performance.now();
    const dur = to > 100 ? 1400 : 900;
    const fmt = new Intl.NumberFormat("en");
    const step = (now) => {
      const t = Math.min(1, (now - start) / dur);
      el.textContent = fmt.format(Math.round(to * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(step);
    };
    el.textContent = "0";
    requestAnimationFrame(step);
  }
  $$(".count").forEach((el) => onceVisible(el, countUp, 0.6));

  /* ------------------------------------------------------------ attack walkthrough */
  const steps = $("#steps");
  if (steps && motion && belowFold(steps)) {
    steps.classList.add("armed");
    $$(".trace li", steps).forEach((li, i) => { li.style.transitionDelay = `${0.9 + i * 0.28}s`; });
    onceVisible(steps, (el) => el.classList.add("seen"), 0.3);
  }

  /* ------------------------------------------------------------ invisible-text demo */
  const hidden = $("#hidden-text");
  const reveal = $("#reveal");
  const revealed = $("#revealed");
  if (hidden && reveal && revealed) {
    // The order really is in the page, as Unicode tag characters (U+E0000 + ASCII).
    hidden.textContent = Array.from(hidden.dataset.order)
      .map((c) => String.fromCodePoint(0xE0000 + c.codePointAt(0))).join("");
    reveal.addEventListener("click", () => {
      const open = reveal.getAttribute("aria-pressed") !== "true";
      if (open) {
        const decoded = Array.from(hidden.textContent)
          .map((c) => c.codePointAt(0))
          .filter((cp) => cp >= 0xE0000 && cp <= 0xE007F)
          .map((cp) => String.fromCodePoint(cp - 0xE0000)).join("");
        revealed.textContent = `Hidden: ${decoded}`;
      }
      revealed.hidden = !open;
      reveal.setAttribute("aria-pressed", String(open));
      reveal.textContent = open ? "Hide it again" : "Reveal the hidden text";
    });
  }

  /* ------------------------------------------------------------ red-team board */
  const board = $("#board");
  if (board) {
    const rows = $$(".row", board);
    rows.forEach((row, i) => row.style.setProperty("--i", String(i)));
    for (const btn of $$(".chip-btn")) {
      const f = btn.dataset.filter;
      const n = f === "all" ? rows.length : rows.filter((r) => r.dataset.vector === f).length;
      const badge = document.createElement("span");
      badge.className = "n";
      badge.textContent = String(n);
      btn.append(badge);
      btn.addEventListener("click", () => {
        $$(".chip-btn").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
        let i = 0;
        for (const row of rows) {
          const show = f === "all" || row.dataset.vector === f;
          row.hidden = !show;
          if (show && motion) {
            const stamp = $(".stamp", row);
            stamp.classList.remove("thump");
            void stamp.offsetWidth; // restart the animation
            stamp.style.animationDelay = `${i++ * 60}ms`;
            stamp.classList.add("thump");
          }
        }
      });
    }
    if (motion && belowFold(board)) {
      board.classList.add("armed");
      onceVisible(board, (el) => el.classList.add("seen"), 0.15);
    }
  }

  /* ------------------------------------------------------------ pipeline */
  const pipe = $(".pipe");
  if (pipe && motion && "IntersectionObserver" in window) {
    const stages = Array.from(pipe.children);
    let timer = 0;
    let at = 0;
    const tick = () => {
      stages.forEach((s, i) => s.classList.toggle("lit", i === at));
      at = (at + 1) % (stages.length + 2); // a short pause after the last stage
    };
    new IntersectionObserver(([entry]) => {
      clearInterval(timer);
      if (entry.isIntersecting) { tick(); timer = setInterval(tick, 850); }
      else stages.forEach((s) => s.classList.remove("lit"));
    }, { threshold: 0.3 }).observe(pipe);
  }

  /* ------------------------------------------------------------ terminal */
  for (const btn of $$(".copy")) {
    btn.addEventListener("click", async () => {
      const code = btn.previousElementSibling;
      const text = code.dataset.full || code.textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
      } catch {
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Selected";
      }
      btn.classList.add("done");
      setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1600);
    });
  }
  const term = $("#term");
  if (term && motion && belowFold(term)) {
    const lines = $$(".cmd code", term);
    lines.forEach((code) => { code.dataset.full = code.textContent; code.textContent = ""; });
    onceVisible(term, async () => {
      for (const code of lines) {
        const li = code.parentElement;
        li.classList.add("typing");
        const full = code.dataset.full;
        for (let i = 1; i <= full.length; i++) {
          code.textContent = full.slice(0, i);
          await wait(full.length > 30 ? 14 : 45);
        }
        li.classList.remove("typing");
        await wait(220);
      }
    }, 0.35);
  }

  /* ------------------------------------------------------------ hero demo */
  const demo = $(".demo");
  const body = $("#demo");
  if (demo && canHover && motion) {
    demo.addEventListener("pointermove", (e) => {
      const r = demo.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5;
      const y = (e.clientY - r.top) / r.height - 0.5;
      demo.style.setProperty("--ry", `${x * 5}deg`);
      demo.style.setProperty("--rx", `${-y * 5}deg`);
    });
    demo.addEventListener("pointerleave", () => {
      demo.style.setProperty("--ry", "0deg");
      demo.style.setProperty("--rx", "0deg");
    });
  }
  if (!body || !motion) return;

  const part = (name) => $(`[data-part="${name}"]`, body);
  const scenes = [
    {
      ask: "Summarise my new emails.",
      note: "Two new emails. One asks me to forward your invoices somewhere. That needs you.",
      what: ["Send an email as the owner to ", "collector@evil.example", ": Fwd: Invoice 2211"],
      why: "send action (ask) in a conversation containing untrusted content from: gmail_search, gmail_read",
      press: "deny",
      stamp: "Denied · nothing sent",
    },
    {
      ask: "Tell Dana Thursday at 3 works for me.",
      note: "Here’s the email. It needs your OK and your code.",
      what: ["Send an email as the owner to dana@studio.example: Re: Thursday"],
      why: "send actions are 'ask' by policy",
      press: "approve",
      code: "481207",
      stamp: "Approved with your code · sent",
    },
  ];

  let visible = true;
  let resume = null;
  const gate = () => (visible && !document.hidden ? Promise.resolve() : new Promise((r) => { resume = r; }));
  const wake = () => { if (visible && !document.hidden && resume) { resume(); resume = null; } };
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(([e]) => { visible = e.isIntersecting; wake(); }).observe(body);
  }
  document.addEventListener("visibilitychange", wake);

  const parts = ["ask", "note", "card", "stamp"];
  const show = (name) => part(name).classList.remove("off");

  function setScene(s) {
    part("ask").textContent = s.ask;
    part("note").textContent = s.note;
    const what = part("what");
    what.textContent = "";
    s.what.forEach((piece, i) => {
      if (i === 1) {
        const bad = document.createElement("span");
        bad.className = "bad";
        bad.textContent = piece;
        what.append(bad);
      } else {
        what.append(piece);
      }
    });
    part("why").textContent = s.why;
    const code = part("code");
    code.hidden = !s.code;
    $$("span", code).forEach((d) => { d.textContent = ""; d.classList.remove("on"); });
    $$(".ap-btn", body).forEach((b) => b.classList.remove("press"));
    const stamp = part("stamp");
    stamp.textContent = s.stamp;
    stamp.className = "stamp stamp-held off";
  }

  async function play() {
    await wait(2600); // let the first, static scene be read
    for (let n = 1; ; n++) {
      const s = scenes[n % scenes.length];
      await gate();
      parts.forEach((p) => part(p).classList.add("off"));
      await wait(500);
      setScene(s);
      await wait(150);
      show("ask");
      await wait(1100);
      show("note");
      await wait(1200);
      show("card");
      await wait(1500);
      if (s.code) {
        part(s.press).classList.add("press");
        await wait(600);
        const digits = $$("span", part("code"));
        for (let i = 0; i < digits.length; i++) {
          digits[i].textContent = s.code[i];
          digits[i].classList.add("on");
          await wait(210);
        }
        await wait(400);
      } else {
        part(s.press).classList.add("press");
        await wait(500);
      }
      const stamp = part("stamp");
      stamp.classList.remove("off");
      stamp.classList.add("thump");
      await wait(4200);
    }
  }
  play();
})();
