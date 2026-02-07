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

// -------------------------------
// AVISOS (+ / -) sin recargar
// -------------------------------
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-avisos");
  if (!btn) return;

  const wrap = btn.closest(".avisos-control");
  if (!wrap) return;

  const id = wrap.dataset.id;
  const action = btn.dataset.action; // inc | dec
  const badge = wrap.querySelector(".aviso-badge");

  if (!id || !action || !badge) return;

  btn.disabled = true;

  try {
    const res = await fetch(`/expedientes/${id}/verificaciones/${action}`, {
      method: "POST",
      headers: { "X-Requested-With": "fetch" },
    });

    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`HTTP ${res.status}: ${txt}`);
    }

    let v = parseInt(badge.textContent, 10) || 0;
    v = action === "inc" ? v + 1 : Math.max(0, v - 1);
    badge.textContent = String(v);

    badge.classList.remove("badge--ok", "badge--warn", "badge--bad");
    if (v <= 1) badge.classList.add("badge--ok");
    else if (v === 2) badge.classList.add("badge--warn");
    else badge.classList.add("badge--bad");
  } catch (err) {
    console.error(err);
    alert("NO SE PUDO ACTUALIZAR LOS AVISOS");
  } finally {
    btn.disabled = false;
  }
});