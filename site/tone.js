// Runs before the page paints, so it never flashes the wrong colours. The page always opens
// pale (data-tone="light" is in the HTML); only a choice the visitor made with the button changes it.
(() => {
  "use strict";
  let saved = null;
  try { saved = window.localStorage.getItem("bastion-tone"); } catch { /* storage blocked */ }
  if (saved === "light" || saved === "dark") document.documentElement.dataset.tone = saved;
})();
