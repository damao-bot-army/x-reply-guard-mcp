/**
 * Every HTML page the Worker serves: the OAuth consent page at /authorize, the draft review page at
 * /admin/approve/<id>, and the result and error pages of both flows.
 *
 * Each page is one self-contained document with no external fonts, images or scripts, so the CSP
 * stays `default-src 'none'`. The inline stylesheet and the small progressive-enhancement scripts
 * run under a random per-response nonce, never 'unsafe-inline'. Inline `style` attributes would be
 * blocked by that policy, so markup uses classes only.
 *
 * The only external link is the published post on https://x.com, shown after a successful approval.
 *
 * Every dynamic value goes through html() from ./security, the same escaping that redact() knows
 * about. Draft text and reply-target content come from an AI client and from X: treat them as hostile.
 */
import { html, MAX_POST_LENGTH, URL_LENGTH } from './security';

/**
 * The directives every page starts from. On /authorize, form-action would apply to the whole
 * redirect chain after submit, and OAuth clients may redirect further, so it is deliberately omitted.
 */
export const BASE_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

const BRAND = 'X Reply Guard';

const ICONS = {
  at: '<circle cx="12" cy="12" r="3.6"/><path d="M15.6 12v1.4a2.6 2.6 0 0 0 5.2 0V12a8.8 8.8 0 1 0-3.4 6.9"/>',
  pencil: '<path d="M4.5 19.5l.9-3.9L15.6 5.4a2.1 2.1 0 0 1 3 3L8.4 18.6z"/><path d="M13.6 7.4l3 3"/>',
  send: '<path d="M20.5 3.5L10.2 13.8"/><path d="M20.5 3.5l-6.3 17-4-6.7-6.7-4z"/>',
  arrows: '<path d="M5 9h14"/><path d="M15.5 5.5L19 9l-3.5 3.5"/><path d="M19 15H5"/><path d="M8.5 11.5L5 15l3.5 3.5"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3.5 3.5l17 17"/><path d="M10.4 5.6A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.8 3.6"/><path d="M6.5 6.9C3.9 8.6 2.5 12 2.5 12S6 18.5 12 18.5a9 9 0 0 0 4.9-1.4"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><path d="M12 14.5v2"/>',
  alert: '<path d="M10.3 4.4L2.8 17.5a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 4.4a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4"/><path d="M12 17h.01"/>',
  shield: '<path d="M12 3.5l7 2.7v5.5c0 4.2-2.9 7.6-7 8.8-4.1-1.2-7-4.6-7-8.8V6.2z"/><path d="M12 8.5v4"/><path d="M12 15.5h.01"/>',
  shieldCheck: '<path d="M12 3.5l7 2.7v5.5c0 4.2-2.9 7.6-7 8.8-4.1-1.2-7-4.6-7-8.8V6.2z"/><path d="M8.9 12.1l2.2 2.2 4-4.2"/>',
  back: '<path d="M9 14.5L4.5 10 9 5.5"/><path d="M4.5 10h10a5 5 0 0 1 0 10H12"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  x: '<path d="M7 7l10 10"/><path d="M17 7L7 17"/>',
  bubble: '<path d="M20 11.5a7.5 7.5 0 0 1-10.9 6.7L4.5 19.5l1.3-4.4A7.5 7.5 0 1 1 20 11.5z"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l2.8-2.8a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-2.8 2.8a4 4 0 0 0 5.7 5.7l1-1"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.4-4.4"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
} as const;
type IconName = keyof typeof ICONS;

const icon = (name: IconName, className = 'icon') =>
  `<svg class="${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;

/** The brand mark: a shield with a speech bubble cut out of it. `id` keeps gradient ids unique per page. */
const logo = (id: string) =>
  `<svg class="logo" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><defs><linearGradient id="${id}" x1="3" y1="2" x2="29" y2="30" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#20c4a2"/><stop offset=".5" stop-color="#0e9483"/><stop offset="1" stop-color="#1c6ed8"/></linearGradient></defs><rect width="32" height="32" rx="9" fill="url(#${id})"/><path d="M16 5.6l8.8 3.2v6.4c0 5.5-3.7 9.7-8.8 11.2-5.1-1.5-8.8-5.7-8.8-11.2V8.8z" fill="#fff"/><path d="M11.9 11.2h8.2a2 2 0 0 1 2 2v4.1a2 2 0 0 1-2 2h-4.3l-2.9 2.4v-2.4h-1a2 2 0 0 1-2-2v-4.1a2 2 0 0 1 2-2z" fill="url(#${id})"/><circle cx="13.3" cy="15.25" r="1.05" fill="#fff"/><circle cx="16" cy="15.25" r="1.05" fill="#fff"/><circle cx="18.7" cy="15.25" r="1.05" fill="#fff"/></svg>`;

const STYLES = `
:root {
  color-scheme: light dark;
  --bg: #f3f6f6;
  --glow-a: rgba(24, 170, 150, .15);
  --glow-b: rgba(40, 120, 230, .10);
  --surface: #fff;
  --surface-2: #f5f7f8;
  --border: rgba(16, 32, 40, .09);
  --border-strong: rgba(16, 32, 40, .22);
  --text: #131a1d;
  --muted: #56626a;
  --accent: #0d7f72;
  --accent-hover: #0b6e63;
  --on-accent: #fff;
  --accent-soft: rgba(13, 127, 114, .09);
  --accent-faint: rgba(13, 127, 114, .045);
  --accent-border: rgba(13, 127, 114, .26);
  --accent-ink: #0b6b61;
  --ring: rgba(13, 127, 114, .26);
  --focus: #0d7f72;
  --danger: #c42840;
  --danger-soft: rgba(220, 50, 72, .1);
  --warning: #8f4c00;
  --warning-soft: rgba(240, 150, 30, .13);
  --warning-border: rgba(200, 120, 20, .3);
  --success: #12804a;
  --success-soft: rgba(30, 160, 90, .12);
  --shadow: 0 1px 2px rgba(16, 32, 40, .05), 0 12px 32px -12px rgba(16, 32, 40, .14), 0 32px 80px -32px rgba(10, 90, 90, .24);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0e0f;
    --glow-a: rgba(24, 190, 165, .17);
    --glow-b: rgba(50, 120, 240, .09);
    --surface: #131a1b;
    --surface-2: #1a2223;
    --border: rgba(255, 255, 255, .08);
    --border-strong: rgba(255, 255, 255, .2);
    --text: #ecf2f2;
    --muted: #9fabb0;
    --accent: #0f8576;
    --accent-hover: #10937f;
    --accent-soft: rgba(45, 212, 191, .13);
    --accent-faint: rgba(45, 212, 191, .05);
    --accent-border: rgba(45, 212, 191, .28);
    --accent-ink: #5eead4;
    --ring: rgba(45, 212, 191, .3);
    --focus: #4fd1c0;
    --danger: #ff7a8f;
    --danger-soft: rgba(255, 100, 125, .14);
    --warning: #ffb85c;
    --warning-soft: rgba(255, 180, 70, .12);
    --warning-border: rgba(255, 180, 70, .3);
    --success: #4ade80;
    --success-soft: rgba(74, 222, 128, .13);
    --shadow: 0 1px 2px rgba(0, 0, 0, .5), 0 32px 80px -32px rgba(0, 0, 0, .8);
  }
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  color: var(--text);
  background:
    radial-gradient(52rem 34rem at 12% -12%, var(--glow-a), transparent 62%),
    radial-gradient(44rem 30rem at 108% 112%, var(--glow-b), transparent 62%),
    var(--bg);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.shell { margin: auto; width: 100%; max-width: 456px; padding: 40px 16px; }
.shell.wide { max-width: 544px; }
.brand { display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 20px; font-weight: 650; font-size: 15px; letter-spacing: -.01em; }
.brand .logo { width: 28px; height: 28px; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 22px;
  box-shadow: var(--shadow);
  padding: 32px;
}
.hero, .message { text-align: center; }
.pair { display: flex; align-items: center; justify-content: center; margin-bottom: 22px; }
.avatar { flex: none; width: 56px; height: 56px; border-radius: 16px; display: grid; place-items: center; }
.avatar.client { background: var(--surface-2); border: 1px solid var(--border); font-size: 24px; font-weight: 650; line-height: 1; }
.avatar .logo { width: 56px; height: 56px; display: block; border-radius: 16px; box-shadow: 0 6px 18px -6px rgba(14, 130, 120, .55); }
.bridge { display: flex; align-items: center; color: var(--muted); }
.bridge::before, .bridge::after { content: ""; width: 20px; border-top: 2px dotted var(--border-strong); }
.bridge .badge { width: 28px; height: 28px; margin: 0 4px; border-radius: 50%; display: grid; place-items: center; background: var(--surface); border: 1px solid var(--border); }
.bridge .icon { width: 15px; height: 15px; }
h1 { margin: 0 0 6px; font-size: 22px; line-height: 1.3; font-weight: 680; letter-spacing: -.02em; overflow-wrap: anywhere; text-wrap: balance; }
.lead { margin: 0; color: var(--muted); text-wrap: pretty; }
code { font: .9em/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 2px 5px; border-radius: 6px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text); white-space: nowrap; }
.section-label { margin: 28px 0 10px; font-size: 12px; font-weight: 650; letter-spacing: .07em; text-transform: uppercase; color: var(--muted); }
.caps { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border); border-radius: 16px; background: var(--surface-2); }
.caps li { display: flex; align-items: center; gap: 14px; padding: 12px 14px; }
.caps li + li { border-top: 1px solid var(--border); }
.caps .tile { flex: none; width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-ink); }
.caps .icon { width: 18px; height: 18px; }
.caps strong { display: block; font-size: 14.5px; font-weight: 620; line-height: 1.35; }
.caps small { display: block; font-size: 13.5px; color: var(--muted); line-height: 1.4; }
form { margin: 26px 0 0; }
label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 620; }
.field { position: relative; }
.field input {
  width: 100%;
  height: 48px;
  padding: 0 52px 0 14px;
  border: 1px solid var(--border-strong);
  border-radius: 12px;
  background: var(--surface);
  color: var(--text);
  font: inherit;
  font-size: 16px;
  outline: none;
  transition: border-color .15s, box-shadow .15s;
}
.field input:hover { border-color: var(--muted); }
.field input:focus { border-color: var(--focus); box-shadow: 0 0 0 4px var(--ring); }
.reveal {
  position: absolute;
  top: 6px;
  right: 6px;
  width: 36px;
  height: 36px;
  padding: 0;
  border: 0;
  border-radius: 9px;
  display: grid;
  place-items: center;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
}
.reveal:hover { background: var(--surface-2); color: var(--text); }
.reveal .icon { width: 20px; height: 20px; }
.reveal .if-revealed, .reveal[aria-pressed="true"] .if-masked { display: none; }
.reveal[aria-pressed="true"] .if-revealed { display: block; }
.hint { margin: 8px 0 0; font-size: 13px; color: var(--muted); }
.actions { display: grid; gap: 10px; margin-top: 24px; }
.button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  height: 48px;
  padding: 0 20px;
  border: 1px solid transparent;
  border-radius: 12px;
  font: inherit;
  font-size: 15px;
  font-weight: 620;
  text-decoration: none;
  cursor: pointer;
  transition: background-color .15s, border-color .15s, box-shadow .15s;
}
.button .icon { width: 18px; height: 18px; }
.primary { background: var(--accent); color: var(--on-accent); box-shadow: 0 1px 2px rgba(16, 32, 40, .14), inset 0 1px 0 rgba(255, 255, 255, .16); }
.primary:hover { background: var(--accent-hover); }
.secondary { background: transparent; color: var(--text); border-color: var(--border-strong); }
.secondary:hover { background: var(--surface-2); }
.button:active { transform: translateY(1px); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.field input:focus-visible { outline: none; }
.status { width: 56px; height: 56px; margin: 0 auto 18px; border-radius: 50%; display: grid; place-items: center; }
.status .icon { width: 26px; height: 26px; }
.status.danger { background: var(--danger-soft); color: var(--danger); }
.status.warning { background: var(--warning-soft); color: var(--warning); }
.status.success { background: var(--success-soft); color: var(--success); }
.status.accent { background: var(--accent-soft); color: var(--accent-ink); }
.status.neutral { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }
.next { display: flex; align-items: center; gap: 12px; margin: 24px 0 0; padding: 14px 16px; border-radius: 14px; background: var(--accent-soft); text-align: left; font-weight: 560; }
.next .icon { flex: none; width: 20px; height: 20px; color: var(--accent-ink); }
.detail { margin: 16px 0 0; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); background: var(--surface-2); text-align: left; font-size: 13px; color: var(--muted); overflow-wrap: anywhere; }
.detail span { display: block; margin-bottom: 2px; font-size: 11.5px; font-weight: 650; letter-spacing: .07em; text-transform: uppercase; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.expiry {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: center;
  gap: 2px 7px;
  margin: 16px 0 0;
  padding: 6px 13px 6px 10px;
  border-radius: 16px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  font-size: 13.5px;
  line-height: 1.45;
  color: var(--muted);
}
.expiry .icon { flex: none; width: 16px; height: 16px; }
.expiry strong { color: var(--text); font-weight: 600; }
.expiry .sep { opacity: .55; }
.expiry time { font-variant-numeric: tabular-nums; }
.callout { display: flex; gap: 12px; margin: 24px 0 0; padding: 14px 16px; border-radius: 14px; border: 1px solid var(--warning-border); background: var(--warning-soft); text-align: left; }
.callout > .icon { flex: none; width: 20px; height: 20px; margin-top: 1px; color: var(--warning); }
.callout strong { display: block; font-weight: 640; color: var(--text); }
.callout p { margin: 1px 0 0; font-size: 14px; color: var(--muted); }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 9px 0 0; padding: 0; list-style: none; }
.chips li { padding: 2px 10px; border-radius: 999px; border: 1px solid var(--warning-border); background: var(--surface); color: var(--warning); font-size: 12.5px; font-weight: 600; line-height: 1.6; overflow-wrap: anywhere; }
.section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin: 26px 0 10px; }
.section-head .section-label { margin: 0; }
.meta { min-width: 0; font-size: 12.5px; color: var(--muted); font-variant-numeric: tabular-nums; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.count { flex: none; font-size: 13px; color: var(--muted); font-variant-numeric: tabular-nums; }
.count strong { color: var(--text); font-weight: 640; }
.count.over { padding: 1px 9px; border-radius: 999px; background: var(--danger-soft); color: var(--danger); font-weight: 600; }
.count.over strong { color: var(--danger); }
.post { padding: 14px 16px; border-radius: 16px; border: 1px solid var(--border); background: var(--surface-2); }
.post-head { display: flex; align-items: center; gap: 10px; min-width: 0; }
.post .initial { flex: none; width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; background: var(--surface); border: 1px solid var(--border); font-weight: 650; line-height: 1; }
.who { min-width: 0; display: flex; flex-direction: column; line-height: 1.3; }
.who strong, .who span { overflow-wrap: anywhere; }
.who strong { font-weight: 630; }
.who span { font-size: 13.5px; color: var(--muted); }
.post-text { margin: 10px 0 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.post-text.missing { margin: 0; color: var(--muted); }
.draft { margin: 0; padding: 16px 18px; border-radius: 16px; border: 1px solid var(--accent-border); background: var(--accent-faint); font-size: 16.5px; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; }
.note { display: flex; gap: 10px; margin: 14px 0 0; font-size: 13.5px; line-height: 1.5; color: var(--muted); text-align: left; }
.note .icon { flex: none; width: 18px; height: 18px; margin-top: 1px; color: var(--accent-ink); }
.divider { height: 1px; margin: 26px 0 0; border: 0; background: var(--border); }
.divider + form { margin-top: 22px; }
@media (max-width: 480px) {
  .shell { padding: 24px 12px; }
  .card { padding: 26px 20px; border-radius: 20px; }
  h1 { font-size: 21px; }
  .draft { padding: 14px 16px; font-size: 16px; }
  .post { padding: 12px 14px; }
}
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; }
}
`;

/** Progressive enhancement for the consent page: reveals the show-password toggle. The form works without it. */
const REVEAL_SCRIPT = `
const input = document.getElementById("password");
const toggle = document.getElementById("reveal");
toggle.hidden = false;
toggle.addEventListener("click", () => {
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  toggle.setAttribute("aria-pressed", String(reveal));
  input.focus();
});
// Submit as a password field so the browser never keeps the value in plain-text form history.
input.form.addEventListener("submit", () => { input.type = "password"; });
`;

/**
 * Progressive enhancement for the review page: shows the expiry in the browser's time zone and keeps
 * the relative time current. Without JavaScript the server-rendered UTC time stays.
 * expiresIn() mirrors the server-side function of the same name below; a test keeps them in sync.
 */
const EXPIRY_SCRIPT = `
const expiresIn = (ms) => {
  if (ms <= 0) return "Expired";
  const minutes = Math.round(ms / 60000);
  if (minutes < 1) return "Expires in under a minute";
  const plural = (n, unit) => "Expires in " + n + " " + unit + (n === 1 ? "" : "s");
  if (minutes < 90) return plural(minutes, "minute");
  const hours = Math.round(minutes / 60);
  return hours < 36 ? plural(hours, "hour") : plural(Math.round(hours / 24), "day");
};
const at = document.getElementById("expires-at");
const label = document.getElementById("expires-in");
const when = new Date(at.dateTime);
const sameDay = when.toDateString() === new Date().toDateString();
at.textContent = when.toLocaleString(undefined, sameDay
  ? { hour: "numeric", minute: "2-digit" }
  : { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
const update = () => { label.textContent = expiresIn(when.getTime() - Date.now()); };
update();
setInterval(update, 15000);
`;

function createNonce(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(18))));
}

interface PageOptions {
  /** Plain text; escaped here. */
  title: string;
  /** Markup built only from static strings and escaped values. */
  body: string;
  status?: number;
  /** Headers to send with the page, such as a cookie; updated in place. */
  headers?: Headers;
  /** A static script; it runs under the same nonce as the stylesheet. */
  script?: string;
  /** A wider card for content-heavy pages. */
  wide?: boolean;
  /** Extra CSP directives appended after the nonce sources. */
  csp?: string;
}

function htmlPage({ title, body, status = 200, headers = new Headers(), script, wide, csp }: PageOptions): Response {
  const nonce = createNonce();
  const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex, nofollow">
<title>${html(title)} · ${BRAND}</title>
<style nonce="${nonce}">${STYLES}</style>
</head>
<body>
<div class="shell${wide ? ' wide' : ''}">
<header class="brand">${logo('brand-logo')}<span>${BRAND}</span></header>
<main class="card">
${body}
</main>
</div>
${script ? `<script nonce="${nonce}">${script}</script>\n` : ''}</body>
</html>
`;
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Security-Policy', `${BASE_CSP}; style-src 'nonce-${nonce}'${script ? `; script-src 'nonce-${nonce}'` : ''}${csp ? `; ${csp}` : ''}`);
  // Not no-referrer: under no-referrer browsers send `Origin: null` on same-origin form POSTs, which
  // the strict Origin checks reject. same-origin still sends nothing to other origins.
  headers.set('Referrer-Policy', 'same-origin');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  return new Response(page, { status, headers });
}

/** The first character of a name, for a letter avatar. */
const initialOf = (name: string) => html(Array.from(name.trim())[0]?.toUpperCase() ?? '?');

/** The password field, its show/hide toggle (enabled by REVEAL_SCRIPT) and a hint. */
const passwordField = (hint: string, autofocus: boolean) => `<label for="password">Password</label>
<div class="field">
<input id="password" type="password" name="password" required${autofocus ? ' autofocus' : ''} autocomplete="current-password" autocapitalize="off" spellcheck="false" maxlength="1024" aria-describedby="password-hint">
<button type="button" class="reveal" id="reveal" aria-label="Show password" aria-pressed="false" aria-controls="password" hidden>${icon('eye', 'icon if-masked')}${icon('eyeOff', 'icon if-revealed')}</button>
</div>
<p class="hint" id="password-hint">${hint}</p>`;

// ---------------------------------------------------------------------------------------------
// OAuth consent (/authorize)
// ---------------------------------------------------------------------------------------------

export interface ConsentView {
  /** May come from the client; escaped here. */
  clientName: string;
  handle: string;
  /** PUBLISH_MODE=auto: safe drafts are published without human approval. */
  autoPublish: boolean;
}

/** The consent form. `headers` are the ones beginConsent() returned; they bind the handle to this browser. */
export function consentPage({ clientName, handle, autoPublish }: ConsentView, headers: Headers): Response {
  const capabilities: [IconName, string, string][] = [
    ['at', 'Read mentions and posts', 'See your mentions and look up posts'],
    ['pencil', 'Create drafts', 'Write posts and replies as drafts'],
    ['send', 'Publish drafts', autoPublish ? 'Automatically, after the safety checks' : 'Only after you approve each one'],
  ];
  const items = capabilities.map(([name, title, description]) =>
    `<li><span class="tile">${icon(name)}</span><span><strong>${title}</strong><small>${description}</small></span></li>`).join('\n');
  return htmlPage({
    title: `Connect ${clientName}`,
    headers,
    script: REVEAL_SCRIPT,
    body: `<div class="hero">
<div class="pair" aria-hidden="true"><span class="avatar client">${initialOf(clientName)}</span><span class="bridge"><span class="badge">${icon('arrows')}</span></span><span class="avatar">${logo('hero-logo')}</span></div>
<h1>${html(clientName)} wants to connect</h1>
<p class="lead">Allow it to use ${BRAND} with your X account?</p>
</div>
<h2 class="section-label" id="capabilities">It will be able to</h2>
<ul class="caps" aria-labelledby="capabilities">
${items}
</ul>
<form method="post" action="/authorize">
<input type="hidden" name="handle" value="${html(handle)}">
${passwordField('The <code>AUTH_PASSWORD</code> set for this server.', true)}
<div class="actions">
<button class="button primary" name="decision" value="approve">Allow</button>
<button class="button secondary" name="decision" value="deny" formnovalidate>Deny</button>
</div>
</form>`,
  });
}

// ---------------------------------------------------------------------------------------------
// Result and error pages
// ---------------------------------------------------------------------------------------------

type Tone = 'danger' | 'warning' | 'success' | 'neutral';

interface MessageView {
  status: number;
  tone: Tone;
  icon: IconName;
  /** Plain text. */
  title: string;
  /** Static markup. */
  message: string;
  /** A same-origin link offered as the next step instead of `next`; escaped here. */
  retryHref?: string;
  /** Static markup for the next step. */
  next: string;
  nextIcon?: IconName;
  /** Plain text, such as an error message; escaped here. */
  detail?: string;
  headers?: Headers;
  /** An absolute https://x.com/ link to the published post; escaped here. */
  postHref?: string;
}

function messagePage(view: MessageView): Response {
  const action = view.postHref
    ? `<div class="actions"><a class="button primary" href="${html(view.postHref)}" rel="noopener noreferrer">${icon('link')}View post on X</a></div>
<p class="next">${icon(view.nextIcon ?? 'check')}<span>${view.next}</span></p>`
    : view.retryHref
      ? `<div class="actions"><a class="button primary" href="${html(view.retryHref)}">Try again</a></div>`
      : `<p class="next">${icon(view.nextIcon ?? 'back')}<span>${view.next}</span></p>`;
  return htmlPage({
    title: view.title,
    status: view.status,
    headers: view.headers,
    body: `<div class="message">
<span class="status ${view.tone}" aria-hidden="true">${icon(view.icon)}</span>
<h1>${html(view.title)}</h1>
<p class="lead">${view.message}</p>
${action}
${view.detail ? `<p class="detail"><span>Details</span>${html(view.detail)}</p>` : ''}
</div>`,
  });
}

const RESTART_SIGN_IN = 'Return to your MCP client and start the sign-in again.';

/**
 * The consent password did not match. `retryHref` is the consent page the form came from: opening it
 * again starts a fresh consent transaction for the same request, exactly like reloading the page.
 */
export function wrongPasswordPage(retryHref?: string): Response {
  return messagePage({
    status: 403, tone: 'danger', icon: 'lock', title: 'Incorrect password', retryHref, next: RESTART_SIGN_IN,
    message: "That doesn't match the <code>AUTH_PASSWORD</code> set for this server, so no access was granted.",
  });
}

export function crossOriginPage(): Response {
  return messagePage({
    status: 403, tone: 'danger', icon: 'shield', title: 'Request blocked', next: RESTART_SIGN_IN,
    message: "Sign-in approvals are only accepted from this server's own authorization page. No access was granted.",
  });
}

export function methodNotAllowedPage(): Response {
  return messagePage({
    status: 405, tone: 'warning', icon: 'alert', title: 'Method not allowed',
    message: 'This address only accepts GET and POST requests.',
    next: 'Start the sign-in from your MCP client.',
    headers: new Headers({ Allow: 'GET, POST' }),
  });
}

/** An AuthorizationError or CimdFetchError without a redirect back to the client. */
export function authorizationFailedPage(reason: string): Response {
  return messagePage({
    status: 400, tone: 'warning', icon: 'alert', title: 'Authorization failed', detail: reason, next: RESTART_SIGN_IN,
    message: "This sign-in request can't be completed. No access was granted.",
  });
}

// ---------------------------------------------------------------------------------------------
// Draft review (/admin/approve/<id>)
// ---------------------------------------------------------------------------------------------

const RISK_LABELS: Record<string, string> = {
  instruction_override: 'Instruction override',
  role_impersonation: 'Role impersonation',
  credential_request: 'Mentions credentials',
  tool_invocation: 'Tool command',
  exfil_url: 'Suspicious link',
  hidden_text: 'Hidden characters',
};

/** "Expires in 29 minutes". EXPIRY_SCRIPT has a browser copy that keeps the label current. */
function expiresIn(ms: number): string {
  if (ms <= 0) return 'Expired';
  const minutes = Math.round(ms / 60000);
  if (minutes < 1) return 'Expires in under a minute';
  const plural = (n: number, unit: string) => `Expires in ${n} ${unit}${n === 1 ? '' : 's'}`;
  if (minutes < 90) return plural(minutes, 'minute');
  const hours = Math.round(minutes / 60);
  return hours < 36 ? plural(hours, 'hour') : plural(Math.round(hours / 24), 'day');
}

/** "2026-11-03 12:30 UTC": the no-JavaScript fallback for the expiry time. */
const utc = (ms: number) => `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

interface ReplyTarget { name: string; username: string; text: string }

/** Reads the target post and its author from the projected (already sanitized) X response stored with the draft. */
function replyTarget(postId: string, info: unknown): ReplyTarget | undefined {
  const record = (value: unknown) => (value && typeof value === 'object' ? value as Record<string, unknown> : {});
  const list = (value: unknown) => (Array.isArray(value) ? value.map(record) : []);
  const text = (value: unknown) => (typeof value === 'string' ? value : '');
  const data = record(info);
  const post = list(data.posts).find(p => p.id === postId);
  if (!post || typeof post.text !== 'string') return undefined;
  const author = list(data.users).find(u => typeof u.id === 'string' && u.id === post.author_id);
  return { name: text(author?.name), username: text(author?.username), text: post.text };
}

export interface ApprovalView {
  id: string;
  /** The verified link signature, submitted back with the form. */
  sig: string;
  csrf: string;
  /** The final draft text. Untrusted. */
  text: string;
  /** postLength() of the text exactly as it will be posted: its length as X counts it (CJK and emoji 2, URLs 23), not code points. */
  length: number;
  riskFlags: string[];
  expires: number;
  now: number;
  target?: string;
  /** The projected X response for the target post. Untrusted. */
  targetInfo?: unknown;
}

/** The review page. `headers` carry the CSRF cookie. */
export function approvalPage(view: ApprovalView, headers: Headers): Response {
  const kind = view.target ? 'reply' : 'post';
  const expiresAt = new Date(view.expires).toISOString();
  const risk = view.riskFlags.length ? `<div class="callout" role="note">
${icon('alert')}
<div><strong>High-risk draft</strong><p>Automatic checks flagged:</p>
<ul class="chips">${view.riskFlags.map(flag => `<li>${html(RISK_LABELS[flag] ?? flag)}</li>`).join('')}</ul></div>
</div>` : '';
  let target = '';
  if (view.target) {
    const info = replyTarget(view.target, view.targetInfo);
    const author = info?.name || (info?.username ? `@${info.username}` : 'Unknown author');
    const post = info
      ? `<div class="post-head"><span class="initial" aria-hidden="true">${initialOf(info.name || info.username || '?')}</span><span class="who"><strong>${html(author)}</strong>${info.name && info.username ? `<span>@${html(info.username)}</span>` : ''}</span></div>
<p class="post-text">${html(info.text)}</p>`
      : `<p class="post-text missing">The original post isn't available.</p>`;
    target = `<section aria-labelledby="target-label">
<div class="section-head"><h2 class="section-label" id="target-label">Replying to</h2><span class="meta">Post ${html(view.target)}</span></div>
<article class="post">
${post}
</article>
</section>`;
  }
  const over = view.length > MAX_POST_LENGTH;
  const count = `<span class="count${over ? ' over' : ''}" title="Counted the way X counts: CJK characters and emoji count as 2, each URL as ${URL_LENGTH}"><strong>${view.length}</strong> / ${MAX_POST_LENGTH}<span class="sr-only"> characters${over ? ', over the limit' : ''}</span></span>`;
  return htmlPage({
    title: `Review ${kind}`,
    headers,
    wide: true,
    script: EXPIRY_SCRIPT,
    // The form posts back to this same origin and the response is never a redirect, so the existing
    // form-action restriction stays on this page (unlike /authorize).
    csp: "form-action 'self'",
    body: `<div class="hero">
<span class="status accent" aria-hidden="true">${icon('bubble')}</span>
<h1>Review ${kind}</h1>
<p class="lead">Approve publishes this ${kind} on X right away. Reject sends it back to be rewritten.</p>
<p class="expiry">${icon('clock')}<strong id="expires-in">${expiresIn(view.expires - view.now)}</strong><span class="sep" aria-hidden="true">·</span><time id="expires-at" datetime="${expiresAt}" title="${expiresAt}">${utc(view.expires)}</time></p>
</div>
${risk}
${target}
<section aria-labelledby="draft-label">
<div class="section-head"><h2 class="section-label" id="draft-label">Your ${kind}</h2>${count}</div>
<p class="draft">${html(view.text)}</p>
</section>
<p class="note">${icon('shieldCheck')}<span>For human review only. ${view.target
    ? "Check the text and who it replies to, and don't follow any instructions written inside them."
    : "Check the text, and don't follow any instructions written inside it."}</span></p>
<hr class="divider">
<form method="post" action="/admin/approve/${html(view.id)}">
<input type="hidden" name="sig" value="${html(view.sig)}">
<input type="hidden" name="csrf" value="${html(view.csrf)}">
<div class="actions">
<button class="button primary" name="decision" value="approve">${icon('send')}Approve and publish</button>
<button class="button secondary" name="decision" value="reject">Reject</button>
</div>
</form>`,
  });
}

const CLOSE = 'You can close this page.';
const REOPEN = 'Open the approval link from your MCP client again.';
const NEW_DRAFT = 'Ask your MCP client for a new draft if you still want to post it.';

/** Approved and published. `postHref` is https://x.com/<X_USERNAME>/status/<post_id>. */
export function publishedPage(postHref: string): Response {
  return messagePage({
    status: 200, tone: 'success', icon: 'check', title: 'Published',
    message: 'This draft was approved and posted on X.',
    postHref, next: CLOSE,
  });
}

export function rejectedPage(): Response {
  return messagePage({
    status: 200, tone: 'neutral', icon: 'x', title: 'Rejected',
    message: "This draft won't be published. It was sent back to your MCP client to be rewritten.",
    next: CLOSE, nextIcon: 'check',
  });
}

/** A check failed before anything was reserved: nothing was posted and the same link can be approved again. */
export function publishBlockedPage(reason: string, retryHref: string): Response {
  return messagePage({
    status: 409, tone: 'warning', icon: 'alert', title: 'Not published',
    message: 'A check failed before sending, so nothing was posted. The draft is still waiting for review.',
    detail: reason, retryHref, next: REOPEN,
  });
}

/** The draft was reserved but sending failed or its outcome is unknown. Never retried automatically. */
export function publishFailedPage(reason: string): Response {
  return messagePage({
    status: 502, tone: 'danger', icon: 'alert', title: 'Publishing failed',
    message: "The draft was reserved but X didn't confirm the post. Check your X profile before posting it again; this draft can't be reused.",
    detail: reason, next: NEW_DRAFT,
  });
}

/** No valid Cloudflare Access session (403), or Access isn't configured or reachable (503). Nothing about the draft is shown. */
export function accessDeniedPage(reason: string, status: 403 | 503): Response {
  return messagePage(status === 403 ? {
    status, tone: 'danger', icon: 'lock', title: 'Sign-in required',
    message: 'Review links only work for reviewers signed in through Cloudflare Access. Nothing was changed.',
    detail: reason, next: 'Sign in through Cloudflare Access, then open the approval link again.',
  } : {
    status, tone: 'warning', icon: 'shield', title: 'Review is unavailable',
    message: "This server can't verify Cloudflare Access right now, so review links are disabled. Nothing was changed.",
    detail: reason, next: 'Ask the server owner to check the Cloudflare Access settings.',
  });
}

type ErrorCopy = Pick<MessageView, 'tone' | 'icon' | 'title' | 'message' | 'next'>;

/** Friendly copy for the errors GuardService.approval() throws, keyed by their exact message. */
const APPROVAL_ERRORS: Record<string, ErrorCopy> = {
  'Draft expired': {
    tone: 'warning', icon: 'clock', title: 'This draft has expired', next: NEW_DRAFT,
    message: 'Its approval window has closed, so it can no longer be approved or rejected.',
  },
  'Draft already processed; cannot approve again': {
    tone: 'neutral', icon: 'check', title: 'Already handled', next: CLOSE,
    message: 'This draft was already rejected or published, so it cannot be decided again.',
  },
  'Invalid approval signature': {
    tone: 'danger', icon: 'link', title: 'Invalid approval link', next: 'Copy the full link from your MCP client and open it again.',
    message: 'This link is incomplete or has been changed, so it cannot be used.',
  },
  'Draft not found': {
    tone: 'warning', icon: 'search', title: 'Draft not found', next: NEW_DRAFT,
    message: "There's no draft at this link. It may have expired and been removed.",
  },
  'CSRF Origin validation failed': {
    tone: 'danger', icon: 'shield', title: 'Request blocked', next: REOPEN,
    message: 'Decisions are only accepted from the approval page itself. Nothing was changed.',
  },
  'CSRF token validation failed': {
    tone: 'danger', icon: 'shield', title: 'Security check failed', next: REOPEN,
    message: "This form's security token didn't match, so nothing was changed.",
  },
};

const UNKNOWN_ERROR: ErrorCopy = {
  tone: 'warning', icon: 'alert', title: "Couldn't process this request", next: REOPEN,
  message: 'Nothing was changed.',
};

/**
 * Any approval failure, as a 403 page. `message` is the (redacted) error GuardService.approval()
 * threw; known ones get friendly copy, anything else is shown as escaped detail.
 */
export function approvalErrorPage(message: string): Response {
  const copy = Object.hasOwn(APPROVAL_ERRORS, message) ? APPROVAL_ERRORS[message] : undefined;
  return messagePage({ status: 403, ...(copy ?? UNKNOWN_ERROR), detail: copy ? undefined : message });
}

export function approvalMethodNotAllowedPage(): Response {
  return messagePage({
    status: 405, tone: 'warning', icon: 'alert', title: 'Method not allowed',
    message: 'Approval links only accept GET and POST requests.', next: REOPEN,
    headers: new Headers({ Allow: 'GET, POST' }),
  });
}
