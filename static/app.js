// ===============================
// app.js — Expedientes DPCJM
// ===============================

// Marca de carga (debug)
document.documentElement.dataset.jsLoaded = "1";
console.log("app.js cargado OK");

// -------------------------------
// Helpers
// -------------------------------
const debounce = (fn, wait = 300) => {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
};

// -------------------------------
// Radios: permitir deseleccionar
// -------------------------------
document.addEventListener("click", (e) => {
  const el = e.target;
  if (!el || el.type !== "radio" || !el.classList.contains("radio-toggle")) return;

  if (el.dataset.waschecked === "1") el.checked = false;

  const group = document.querySelectorAll(
    `input[type="radio"][name="${el.name}"].radio-toggle`
  );
  group.forEach((r) => (r.dataset.waschecked = "0"));
  el.dataset.waschecked = el.checked ? "1" : "0";
});

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('input[type="radio"].radio-toggle').forEach((r) => {
    r.dataset.waschecked = r.checked ? "1" : "0";
  });
});

// -------------------------------
// Tema claro / oscuro (robusto)
// -------------------------------
(() => {
  const root = document.documentElement;
  const btn = document.getElementById("themeToggle");
  if (!btn) return;

  const applyTheme = (t) => {
    root.dataset.theme = t; // "dark" | "light"
    localStorage.setItem("theme", t);
  };

  const saved = localStorage.getItem("theme");
  if (saved === "dark" || saved === "light") {
    applyTheme(saved);
  } else {
    const prefersDark =
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(prefersDark ? "dark" : "light");
  }

  btn.addEventListener("click", () => {
    const current = root.dataset.theme === "dark" ? "dark" : "light";
    applyTheme(current === "dark" ? "light" : "dark");
  });
})();

// -------------------------------
// INDEX: Select all (Bulk)
// -------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const selectAll = document.getElementById("selectAll");
  if (!selectAll) return;

  selectAll.addEventListener("change", () => {
    document
      .querySelectorAll('input[name="expediente_ids"]')
      .forEach((cb) => (cb.checked = selectAll.checked));
  });
});

// -------------------------------
// INDEX: Live Search (SIN RECARGAR)
// Filtra filas usando data-search
// -------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("q");
  const tbody = document.getElementById("expBody");
  const countLabel = document.getElementById("countLabel");
  if (!input || !tbody) return;

  const rows = Array.from(tbody.querySelectorAll(".rowExp"));

  const applyFilter = () => {
    const q = (input.value || "").trim().toLowerCase();
    let visible = 0;

    rows.forEach((tr) => {
      const hay = (tr.dataset.search || "");
      const show = !q || hay.includes(q);
      tr.style.display = show ? "" : "none";
      if (show) visible++;
    });

    if (countLabel) countLabel.textContent = String(visible);
  };

  // filtra al escribir (con debounce para suavidad)
  const debounced = debounce(applyFilter, 120);
  input.addEventListener("input", debounced);

  // si la página carga con ?q=..., aplica filtro una vez
  applyFilter();
});
// -------------------------------
// INDEX: Orden en el FRONT por expediente_code (YY, MM, NNNN)
// NOTA: Solo presentacion. Si ya ordenas desde SQL, puedes quitarlo.
// -------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const tbody = document.getElementById("expBody");
  if (!tbody) return;

  const rows = Array.from(document.querySelectorAll(".rowExp"));
  if (!rows.length) return;

  const params = new URLSearchParams(window.location.search);
  const sort = (params.get("sort") || "desc").trim().toLowerCase(); // asc|desc

  const toInt = (s) => {
    const n = parseInt(s, 10);
    return Number.isFinite(n) ? n : 0;
  };

  rows.sort((a, b) => {
    const ayy = toInt(a.dataset.yy);
    const byy = toInt(b.dataset.yy);
    if (ayy !== byy) return sort === "asc" ? ayy - byy : byy - ayy;

    const amm = toInt(a.dataset.mm);
    const bmm = toInt(b.dataset.mm);
    if (amm !== bmm) return sort === "asc" ? amm - bmm : bmm - amm;

    const anum = toInt(a.dataset.num);
    const bnum = toInt(b.dataset.num);
    if (anum !== bnum) return sort === "asc" ? anum - bnum : bnum - anum;

    return 0;
  });

  rows.forEach((r) => tbody.appendChild(r));
});

