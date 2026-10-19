(function () {
"use strict";

var KEY = "cybersentinel.preferences";
var DEFAULTS = { theme: "deep", layout: "vertical", language: "bn" };

var THEMES = {
  deep:     { bg:"#000000", panel:"#101010", line:"#292929", accent:"#40E0C0", text:"#F5F7FA", muted:"#9CA3AF" },
  midnight: { bg:"#0B1120", panel:"#141E30", line:"#2C3B50", accent:"#38D9C0", text:"#EEF5FF", muted:"#9CACC3" },
  matrix:   { bg:"#020602", panel:"#091109", line:"#203520", accent:"#39FF14", text:"#E9FFE7", muted:"#9BB49A" },
  purple:   { bg:"#0B0812", panel:"#15101F", line:"#352745", accent:"#A78BFA", text:"#F5F0FF", muted:"#B8AACB" },
  light:    { bg:"#F4F6FA", panel:"#FFFFFF", line:"#D9E0EA", accent:"#147D71", text:"#152033", muted:"#5C6B7E" }
};

var ICONS = {
  shield: '<path d="M12 2.5 20 5.5v6.1c0 5-3.4 8.3-8 10.2-4.6-1.9-8-5.2-8-10.2V5.5L12 2.5Z"/><circle cx="12" cy="10.3" r="2.7"/><path d="M12 13v3.5"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  chat: '<path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.4 8.4 0 0 1 3.8-.9h.5a8.5 8.5 0 0 1 8 8z"/>',
  scanner: '<path d="M10 3H5a2 2 0 0 0-2 2v5"/><path d="M14 3h5a2 2 0 0 1 2 2v5"/><path d="M3 14v5a2 2 0 0 0 2 2h5"/><path d="M14 21h5a2 2 0 0 0 2-2v-5"/><circle cx="10.5" cy="10.5" r="4"/><path d="m13.5 13.5 4 4"/>',
  reports: '<path d="M4 19V5"/><path d="M4 19h17"/><path d="m7 14 4-4 3 3 6-7"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.7 1l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.7-1l-1.7.6-1.4-2.4L7.3 15a8 8 0 0 1 0-2l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.7-1l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.7 1l1.7-.6 1.4 2.4-1.4 1.1a8 8 0 0 1-.1 2z"/>'
};

var NAV = [
  { id: "chat",     href: "/" },
  { id: "scanner",  href: "/static/scanner.html" },
  { id: "reports",  href: "/static/reports.html" },
  { id: "history",  href: "/static/history.html" },
  { id: "settings", href: "/static/settings.html" }
];

var LABELS = {
  bn: { chat:"চ্যাট", scanner:"স্ক্যানার", reports:"রিপোর্ট", history:"ইতিহাস", settings:"সেটিংস",
        note:"শুধু অনুমোদিত ওয়েবসাইট পরীক্ষা করো।", open:"মেনু খোলো", close:"মেনু বন্ধ করো",
        lang:"English", navLabel:"প্রধান মেনু" },
  en: { chat:"Chat", scanner:"Scanner", reports:"Reports", history:"History", settings:"Settings",
        note:"Only test authorized websites.", open:"Open menu", close:"Close menu",
        lang:"বাংলা", navLabel:"Main navigation" }
};

function has(obj, key) { return Object.prototype.hasOwnProperty.call(obj, key); }

function readRaw() {
  try {
    var p = JSON.parse(localStorage.getItem(KEY) || "{}");
    return p && typeof p === "object" && !Array.isArray(p) ? p : {};
  } catch (_) { return {}; }
}

function readPrefs() {
  var r = readRaw();
  return {
    theme: typeof r.theme === "string" && has(THEMES, r.theme) ? r.theme : DEFAULTS.theme,
    layout: r.layout === "vertical" || r.layout === "horizontal" ? r.layout : DEFAULTS.layout,
    language: r.language === "bn" || r.language === "en" ? r.language : DEFAULTS.language
  };
}

var state = readPrefs();
var opts = { dict: { bn: {}, en: {} }, onChange: null };
var ready = false;

function $(id) { return document.getElementById(id); }

function applyTheme() {
  var root = document.documentElement;
  var th = THEMES[state.theme];
  Object.keys(th).forEach(function (k) { root.style.setProperty("--" + k, th[k]); });
  root.style.colorScheme = state.theme === "light" ? "light" : "dark";
  root.lang = state.language;
}

function svg(inner) {
  return '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">' + inner + "</svg>";
}

function menuIsOpen() { return document.body.classList.contains("menu-open"); }

function updateMenuButton() {
  var b = $("menuButton");
  if (!b) return;
  var open = menuIsOpen();
  b.setAttribute("aria-expanded", String(open));
  b.setAttribute("aria-label", LABELS[state.language][open ? "close" : "open"]);
}

function closeMenu() {
  if (!menuIsOpen()) return;
  document.body.classList.remove("menu-open");
  updateMenuButton();
}

function openMenu() {
  document.body.classList.add("menu-open");
  updateMenuButton();
}

function build() {
  var layout = $("layout");
  var page = document.body.getAttribute("data-page");

  var aside = document.createElement("aside");
  aside.className = "sidebar";
  aside.id = "sidebar";

  var html = '<div class="brand">' + svg(ICONS.shield) + "<span>CyberSentinel AI</span></div>";
  html += '<nav class="nav" id="mainNav">';
  NAV.forEach(function (n) {
    html += '<a href="' + n.href + '"' + (n.id === page ? ' class="active" aria-current="page"' : "") + ">" +
            svg(ICONS[n.id]) + '<span id="nav-' + n.id + '"></span></a>';
  });
  html += '</nav>';
  html += '<div class="sidebar-foot"><p class="sidebar-note" id="sideNote"></p>' +
          '<button type="button" id="languageButton" class="lang-mini" aria-label="Language"></button></div>';
  aside.innerHTML = html;

  var overlay = document.createElement("div");
  overlay.className = "overlay";
  overlay.id = "overlay";
  overlay.setAttribute("aria-hidden", "true");

  layout.prepend(aside, overlay);

  var topLeft = document.querySelector(".top-left");
  if (topLeft) {
    var mb = document.createElement("button");
    mb.type = "button";
    mb.id = "menuButton";
    mb.className = "menu-button";
    mb.setAttribute("aria-controls", "sidebar");
    mb.setAttribute("aria-expanded", "false");
    mb.innerHTML = svg(ICONS.menu);
    topLeft.prepend(mb);
    mb.addEventListener("click", function () {
      if (menuIsOpen()) { closeMenu(); } else { openMenu(); }
    });
  }

  $("languageButton").addEventListener("click", function () {
    api.set({ language: state.language === "bn" ? "en" : "bn" });
  });

  if (!document.querySelector('link[rel="icon"]')) {
    var icon = document.createElement("link");
    icon.rel = "icon";
    icon.type = "image/svg+xml";
    icon.href = "/static/favicon.svg";
    document.head.appendChild(icon);
  }

  overlay.addEventListener("click", closeMenu);
  aside.querySelectorAll(".nav a").forEach(function (a) { a.addEventListener("click", closeMenu); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && menuIsOpen()) {
      closeMenu();
      var b = $("menuButton");
      if (b) b.focus();
    }
  });
  window.addEventListener("resize", function () { if (window.innerWidth >= 760) closeMenu(); });
}

function render() {
  applyTheme();
  if (!ready) return;

  var L = LABELS[state.language];
  $("layout").className = "layout " + state.layout;

  NAV.forEach(function (n) { $("nav-" + n.id).textContent = L[n.id]; });
  $("sideNote").textContent = L.note;
  $("mainNav").setAttribute("aria-label", L.navLabel);
  $("sidebar").setAttribute("aria-label", L.navLabel);
  var lb = $("languageButton");
  if (lb) lb.textContent = L.lang;
  updateMenuButton();

  var d = (opts.dict && opts.dict[state.language]) || {};
  document.querySelectorAll("[data-i]").forEach(function (el) {
    var v = d[el.getAttribute("data-i")];
    if (v !== undefined) el.textContent = v;
  });
  document.querySelectorAll("[data-ph]").forEach(function (el) {
    var v = d[el.getAttribute("data-ph")];
    if (v !== undefined) el.setAttribute("placeholder", v);
  });

  if (typeof opts.onChange === "function") opts.onChange(state);
}

var api = {
  DEFAULTS: DEFAULTS,
  prefs: function () { return { theme: state.theme, layout: state.layout, language: state.language }; },
  t: function (key) {
    var d = (opts.dict && opts.dict[state.language]) || {};
    return d[key] !== undefined ? d[key] : key;
  },
  set: function (patch) {
    var next = { theme: state.theme, layout: state.layout, language: state.language };
    Object.keys(patch).forEach(function (k) { next[k] = patch[k]; });
    if (!has(THEMES, next.theme)) next.theme = DEFAULTS.theme;
    if (next.layout !== "vertical" && next.layout !== "horizontal") next.layout = DEFAULTS.layout;
    if (next.language !== "bn" && next.language !== "en") next.language = DEFAULTS.language;
    state = next;
    var saved = true;
    try {
      // Merge: keep any unrelated stored fields.
      var merged = readRaw();
      merged.theme = next.theme;
      merged.layout = next.layout;
      merged.language = next.language;
      localStorage.setItem(KEY, JSON.stringify(merged));
    } catch (_) { saved = false; }
    render();
    return saved;
  },
  init: function (options) {
    opts = options || opts;
    build();
    ready = true;
    render();
  }
};

window.CS = api;
applyTheme(); // apply theme early to avoid a flash
})();
