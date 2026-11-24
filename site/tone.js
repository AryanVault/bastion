// Runs before the page paints, so it never flashes the wrong colours. The visitor's saved
// choice wins; otherwise their system setting picks: light gets the pale page, dark the blue one.
(() => {
  "use strict";
  let tone = null;
  try { tone = window.localStorage.getItem("bastion-tone"); } catch { /* storage blocked */ }
  if (tone !== "light" && tone !== "dark") {
    tone = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.dataset.tone = tone;
})();
