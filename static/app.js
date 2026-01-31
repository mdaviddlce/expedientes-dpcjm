// ===============================
// app.js — Expedientes DPCJM
// ===============================

// Marca de carga (debug)
document.documentElement.dataset.jsLoaded = "1";
console.log("app.js cargado OK");

// -------------------------------
// Radios: permitir deseleccionar
// -------------------------------
document.addEventListener("click", (e) => {
  const el = e.target;
  if (!el || el.type !== "radio" || !el.classList.contains("radio-toggle")) return;

  if (el.dataset.waschecked === "1") {
    el.checked = false;
  }

  const group = document.querySelectorAll(
    `input[type="radio"][name="${el.name}"].radio-toggle`
  );
  group.forEach(r => r.dataset.waschecked = "0");
  el.dataset.waschecked = el.checked ? "1" : "0";
});

// Inicializa radios precargados
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('input[type="radio"].radio-toggle').forEach(r => {
    r.dataset.waschecked = r.checked ? "1" : "0";
  });
});

// -------------------------------
// Select all (ZIP)
// -------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const selectAll = document.getElementById("selectAll");
  if (!selectAll) return;

  selectAll.addEventListener("change", () => {
    document.querySelectorAll('input[name="expediente_ids"]').forEach(cb => {
      cb.checked = selectAll.checked;
    });
  });
});


// -------------------------------
// Tema claro / oscuro (robusto)
// -------------------------------
(function () {
  const root = document.documentElement;
  const btn = document.getElementById("themeToggle");
  if (!btn) return;

  const applyTheme = (t) => {
    root.dataset.theme = t;            // "dark" | "light"
    localStorage.setItem("theme", t);
  };

  // aplica tema guardado (default: system->light o dark según pref)
  const saved = localStorage.getItem("theme");
  if (saved === "dark" || saved === "light") {
    applyTheme(saved);
  } else {
    // si no hay guardado, respeta sistema
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(prefersDark ? "dark" : "light");
  }

  btn.addEventListener("click", () => {
    const current = root.dataset.theme === "dark" ? "dark" : "light";
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
  });
})();


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
      headers: {
        "X-Requested-With": "fetch"
      }
    });

    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`HTTP ${res.status}: ${txt}`);
    }

    // Actualiza UI
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
// ===============================
// MENU ACCIONES (⋯)
// ===============================
document.addEventListener("click", (e) => {
  // Click en botón ⋯
  const trigger = e.target.closest(".actions-menu__trigger");

  // Cierra todos los menús abiertos si haces click fuera
  document.querySelectorAll(".actions-menu.is-open").forEach(menu => {
    if (!menu.contains(e.target)) {
      menu.classList.remove("is-open");
    }
  });

  if (!trigger) return;

  const menu = trigger.closest(".actions-menu");
  if (!menu) return;

  // Toggle del menú actual
  menu.classList.toggle("is-open");
});