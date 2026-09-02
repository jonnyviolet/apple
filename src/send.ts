import type { Env, PassRecord } from "./env";

/**
 * Browser console for broadcasting an announcement. The page itself is public
 * (it holds no secret); every action it performs is authorised by the admin
 * token or password the operator types in, which the browser keeps in localStorage.
 */
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#a821f5">
<title>jonny HQ &mdash; send</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; padding: env(safe-area-inset-top) 20px 40px;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 18px; background: #a821f5; color: #feffff;
    font: 17px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  main { width: 100%; max-width: 420px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  p.sub { margin: 0 0 22px; opacity: .75; font-size: 15px; }
  label { display: block; font-size: 13px; text-transform: uppercase;
          letter-spacing: .08em; opacity: .75; margin-bottom: 8px; }
  input, textarea, button {
    width: 100%; font: inherit; border-radius: 14px; border: 0; padding: 14px 16px;
  }
  input, textarea {
    background: rgba(0,0,0,.22); color: #feffff; resize: none;
    border: 1px solid rgba(255,255,255,.25);
  }
  input:focus, textarea:focus { outline: 2px solid #feffff; outline-offset: 1px; }
  button {
    margin-top: 14px; background: #feffff; color: #a821f5; font-weight: 600;
    cursor: pointer; -webkit-appearance: none;
  }
  button:disabled { opacity: .5; cursor: default; }
  .card { background: rgba(0,0,0,.18); border-radius: 18px; padding: 16px; margin-bottom: 20px; }
  .card b { display: block; font-size: 19px; margin-top: 4px; word-break: break-word; }
  .row { display: flex; justify-content: space-between; font-size: 13px; opacity: .75; }
  .count { text-align: right; font-size: 13px; opacity: .7; margin-top: 6px; }
  #status { margin-top: 16px; font-size: 15px; min-height: 22px; }
  #status.err { color: #ffd7d7; }
  .link { display: inline-block; margin-top: 20px; font-size: 13px; opacity: .6;
          color: inherit; background: none; width: auto; padding: 0; text-decoration: underline; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<main>
  <section id="gate" hidden>
    <h1>jonny HQ</h1>
    <p class="sub">admin token or password to continue</p>
    <label for="token">token or password</label>
    <input id="token" type="password" autocomplete="current-password" enterkeyhint="go">
    <button id="unlock">unlock</button>
    <div id="gate-status"></div>
  </section>

  <section id="app" hidden>
    <h1>send an announcement</h1>
    <p class="sub">every pass holder gets a notification</p>
    <div class="card">
      <div class="row"><span>showing now</span><span id="devices"></span></div>
      <b id="current">&mdash;</b>
      <button class="link" id="clear" hidden>clear it from the pass</button>
    </div>
    <label for="message">new message</label>
    <textarea id="message" rows="2" maxlength="60" enterkeyhint="send"
              placeholder="new song out now"></textarea>
    <div class="count"><span id="count">0</span>/60</div>
    <button id="send">send to everyone</button>
    <div id="status"></div>
    <button class="link" id="forget">forget token or password</button>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const KEY = "jonnyhq.admin";
let token = localStorage.getItem(KEY) || "";

const api = (path, options = {}) =>
  fetch(path, {
    ...options,
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
  });

function show(section) {
  $("gate").hidden = section !== "gate";
  $("app").hidden = section !== "app";
}

function say(text, isError) {
  $("status").textContent = text;
  $("status").className = isError ? "err" : "";
}

async function load() {
  const res = await api("/send/state");
  if (!res.ok) {
    token = "";
    localStorage.removeItem(KEY);
    show("gate");
    return false;
  }
  const state = await res.json();
  $("current").textContent = state.value || "(blank)";
  $("clear").hidden = !state.value;
  $("devices").textContent =
    state.devices === 1 ? "1 device" : state.devices + " devices";
  show("app");
  return true;
}

$("unlock").onclick = async () => {
  token = $("token").value.trim();
  if (!token) return;
  $("gate-status").textContent = "checking\\u2026";
  const ok = await load();
  $("gate-status").textContent = ok ? "" : "that token or password didn't work";
  if (ok) localStorage.setItem(KEY, token);
};

$("token").onkeydown = (e) => { if (e.key === "Enter") $("unlock").click(); };

$("message").oninput = () => { $("count").textContent = $("message").value.length; };

$("send").onclick = async () => {
  const message = $("message").value.trim();
  if (!message) return say("type something first", true);
  $("send").disabled = true;
  say("sending\\u2026");
  try {
    const res = await api("/send/announce", {
      method: "POST",
      body: JSON.stringify({ message }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || "failed");
    const p = body.push;
    say(
      p.delivered === 0
        ? "saved, but no devices are registered yet"
        : "sent to " + p.delivered + (p.delivered === 1 ? " device" : " devices"),
    );
    $("message").value = "";
    $("count").textContent = "0";
    await load();
  } catch (err) {
    say(String(err.message || err), true);
  } finally {
    $("send").disabled = false;
  }
};

$("clear").onclick = async () => {
  $("clear").disabled = true;
  say("clearing\\u2026");
  try {
    const res = await api("/send/clear", { method: "POST" });
    if (!res.ok) throw new Error("failed");
    say("cleared \\u2014 no notification sent");
    await load();
  } catch (err) {
    say(String(err.message || err), true);
  } finally {
    $("clear").disabled = false;
  }
};

$("forget").onclick = () => {
  localStorage.removeItem(KEY);
  token = "";
  $("token").value = "";
  show("gate");
};

if (token) { load(); } else { show("gate"); }
</script>
</body>
</html>`;

export function sendPage(): Response {
  return new Response(PAGE, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

type Json = Record<string, unknown>;

function isPlainObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Current value of the announcement field, as stored in the pass's overrides. */
function readAnnouncement(pass: PassRecord): string {
  try {
    const parsed: unknown = JSON.parse(pass.overrides || "{}");
    if (!isPlainObject(parsed)) return "";
    const style = parsed["eventTicket"];
    if (!isPlainObject(style)) return "";
    const fields = style["auxiliaryFields"];
    if (!Array.isArray(fields)) return "";
    const field = fields.find((f) => isPlainObject(f) && f["key"] === ANNOUNCEMENT_FIELD);
    return isPlainObject(field) && typeof field["value"] === "string" ? field["value"] : "";
  } catch {
    return "";
  }
}

/** The auxiliary field carrying `changeMessage`. */
export const ANNOUNCEMENT_FIELD = "announcement";

export function announcementOverrides(pass: PassRecord, message: string): string {
  let overrides: Json = {};
  try {
    const parsed: unknown = JSON.parse(pass.overrides || "{}");
    if (isPlainObject(parsed)) overrides = parsed;
  } catch {
    // Replace anything unparseable rather than refusing to send.
  }

  const style = isPlainObject(overrides["eventTicket"]) ? overrides["eventTicket"] : {};
  const existingAuxiliary = Array.isArray(style["auxiliaryFields"])
    ? style["auxiliaryFields"]
    : [];
  const auxiliaryOthers = existingAuxiliary.filter(
    (f) => !(isPlainObject(f) && f["key"] === ANNOUNCEMENT_FIELD),
  );
  const existingHeader = Array.isArray(style["headerFields"]) ? style["headerFields"] : [];
  const headerOthers = existingHeader.filter(
    (f) => !(isPlainObject(f) && f["key"] === "member"),
  );
  const { headerFields: _headerFields, ...styleWithoutHeaders } = style;
  const eventTicket: Json = {
    ...styleWithoutHeaders,
    auxiliaryFields: [
      ...auxiliaryOthers,
      { key: ANNOUNCEMENT_FIELD, value: message },
    ],
  };
  if (headerOthers.length > 0) eventTicket.headerFields = headerOthers;

  return JSON.stringify({
    ...overrides,
    eventTicket,
  });
}

/**
 * Blank the announcement without pushing, and without bumping `updated_at`:
 * both would make Wallet re-notify, this time with empty text. Holders keep the
 * last announcement until the next one replaces it; anyone installing the pass
 * from here on gets a clean pass.
 */
export async function clearAnnouncement(env: Env, pass: PassRecord): Promise<Response> {
  await env.DB.prepare("UPDATE passes SET overrides = ? WHERE serial_number = ?")
    .bind(announcementOverrides(pass, ""), pass.serial_number)
    .run();

  return Response.json({ serialNumber: pass.serial_number, value: "" });
}

export async function sendState(env: Env, pass: PassRecord): Promise<Response> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM registrations WHERE serial_number = ?",
  )
    .bind(pass.serial_number)
    .first<{ n: number }>();

  return Response.json({
    value: readAnnouncement(pass),
    devices: row?.n ?? 0,
    updatedAt: pass.updated_at,
  });
}
