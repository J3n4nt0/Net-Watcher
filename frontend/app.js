// NetWatch - shared frontend helpers
const API_BASE = "http://127.0.0.1:5000";

function getSession() {
  try {
    return JSON.parse(localStorage.getItem("netwatch_session") || "null");
  } catch {
    return null;
  }
}

function requireAuth() {
  const session = getSession();
  if (!session || !session.token) {
    window.location.href = "index.html";
    return null;
  }
  return session;
}

function logoutAndRedirect() {
  localStorage.removeItem("netwatch_session");
  window.location.href = "index.html";
}

// Wrapper around fetch that injects the auth header and handles 401s.
async function api(path, options = {}) {
  const session = getSession();
  const headers = Object.assign({}, options.headers || {});
  if (session && session.token) {
    headers["Authorization"] = `Bearer ${session.token}`;
  }
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    logoutAndRedirect();
    throw new Error("Session expired");
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const errBody = await res.json();
      detail = errBody.detail || detail;
    } catch {}
    throw new Error(detail);
  }

  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function renderNav(active) {
  const session = getSession();
  const nav = document.getElementById("nav");
  if (!nav) return;
  const links = [
    { href: "dashboard.html", label: "Dashboard" },
    { href: "devices.html", label: "Devices" },
    { href: "tools.html", label: "Tools" },
    { href: "backups.html", label: "Backups" },
  ];
  if (session && session.role === "admin") {
    links.push({ href: "users.html", label: "Users" });
  }
  nav.innerHTML = `
    <div class="nav-inner">
      <span class="brand">NetWatch</span>
      <span class="nav-user">${session ? session.username + " (" + session.role + ")" : ""}</span>
      <button class="nav-toggle" id="navToggle" aria-label="Toggle menu" aria-expanded="false">☰</button>
      <div class="nav-links" id="navLinks">
        ${links.map(l => `<a href="${l.href}" class="${l.href === active ? 'active' : ''}">${l.label}</a>`).join("")}
        <button class="nav-logout" onclick="logoutAndRedirect()">Logout</button>
      </div>
    </div>
  `;

  const toggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");
  toggle.addEventListener("click", () => {
    const isOpen = navLinks.classList.toggle("open");
    toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
  });
}

function timeAgo(isoString) {
  if (!isoString) return "never";
  const then = new Date(isoString + (isoString.endsWith("Z") ? "" : "Z"));
  const diffSec = Math.floor((Date.now() - then.getTime()) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}
