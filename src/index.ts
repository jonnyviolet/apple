import type { Env, PassRecord, RegistrationRecord } from "./env";
import { buildSignedPass } from "./pkpass";
import { isStaleToken, pushToDevices } from "./apns";

const PKPASS_CONTENT_TYPE = "application/vnd.apple.pkpass";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time-ish comparison so token checks don't leak length/prefix. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function loadPass(env: Env, serialNumber: string): Promise<PassRecord | null> {
  return env.DB.prepare("SELECT * FROM passes WHERE serial_number = ?")
    .bind(serialNumber)
    .first<PassRecord>();
}

/**
 * Wallet authenticates every web service call with the pass's own token:
 *   Authorization: ApplePass <authenticationToken>
 */
async function authorizePass(
  request: Request,
  env: Env,
  serialNumber: string,
): Promise<PassRecord | null> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("ApplePass ")) return null;
  const token = header.slice("ApplePass ".length).trim();

  const pass = await loadPass(env, serialNumber);
  if (!pass) return null;
  return safeEqual(token, pass.authentication_token) ? pass : null;
}

function authorizeAdmin(request: Request, env: Env): boolean {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return false;
  return safeEqual(header.slice("Bearer ".length).trim(), env.ADMIN_TOKEN);
}

async function registerDevice(
  request: Request,
  env: Env,
  deviceLibraryIdentifier: string,
  serialNumber: string,
): Promise<Response> {
  const pass = await authorizePass(request, env, serialNumber);
  if (!pass) return new Response("Unauthorized", { status: 401 });

  let pushToken: string;
  try {
    const body = (await request.json()) as { pushToken?: unknown };
    if (typeof body.pushToken !== "string" || body.pushToken.length === 0) {
      return new Response("Bad Request", { status: 400 });
    }
    pushToken = body.pushToken;
  } catch {
    return new Response("Bad Request", { status: 400 });
  }

  const existing = await env.DB.prepare(
    "SELECT * FROM registrations WHERE device_library_identifier = ? AND serial_number = ?",
  )
    .bind(deviceLibraryIdentifier, serialNumber)
    .first<RegistrationRecord>();

  await env.DB.prepare(
    `INSERT INTO registrations (device_library_identifier, serial_number, push_token, created_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (device_library_identifier, serial_number)
     DO UPDATE SET push_token = excluded.push_token`,
  )
    .bind(deviceLibraryIdentifier, serialNumber, pushToken, now())
    .run();

  // 200 tells Wallet the device was already registered, 201 that it is new.
  return new Response(null, { status: existing ? 200 : 201 });
}

async function unregisterDevice(
  request: Request,
  env: Env,
  deviceLibraryIdentifier: string,
  serialNumber: string,
): Promise<Response> {
  const pass = await authorizePass(request, env, serialNumber);
  if (!pass) return new Response("Unauthorized", { status: 401 });

  await env.DB.prepare(
    "DELETE FROM registrations WHERE device_library_identifier = ? AND serial_number = ?",
  )
    .bind(deviceLibraryIdentifier, serialNumber)
    .run();

  return new Response(null, { status: 200 });
}

async function listUpdatedSerials(
  request: Request,
  env: Env,
  deviceLibraryIdentifier: string,
): Promise<Response> {
  const since = new URL(request.url).searchParams.get("passesUpdatedSince");
  const sinceValue = since ? Number.parseInt(since, 10) : 0;
  const threshold = Number.isFinite(sinceValue) ? sinceValue : 0;

  const { results } = await env.DB.prepare(
    `SELECT p.serial_number, p.updated_at
       FROM registrations r
       JOIN passes p ON p.serial_number = r.serial_number
      WHERE r.device_library_identifier = ? AND p.updated_at > ?`,
  )
    .bind(deviceLibraryIdentifier, threshold)
    .all<{ serial_number: string; updated_at: number }>();

  if (!results || results.length === 0) {
    // 204 means "nothing changed"; Wallet treats a 200 with an empty list as an error.
    return new Response(null, { status: 204 });
  }

  const lastUpdated = Math.max(...results.map((row) => row.updated_at));
  return json({
    serialNumbers: results.map((row) => row.serial_number),
    lastUpdated: String(lastUpdated),
  });
}

async function getLatestPass(
  request: Request,
  env: Env,
  serialNumber: string,
): Promise<Response> {
  const pass = await authorizePass(request, env, serialNumber);
  if (!pass) return new Response("Unauthorized", { status: 401 });

  const modifiedSince = request.headers.get("if-modified-since");
  if (modifiedSince) {
    const clientTime = Date.parse(modifiedSince);
    if (Number.isFinite(clientTime) && pass.updated_at * 1000 <= clientTime) {
      return new Response(null, { status: 304 });
    }
  }

  const bytes = await buildSignedPass(env, pass);
  return new Response(bytes, {
    status: 200,
    headers: {
      "content-type": PKPASS_CONTENT_TYPE,
      "last-modified": new Date(pass.updated_at * 1000).toUTCString(),
      "content-disposition": `attachment; filename="${serialNumber}.pkpass"`,
    },
  });
}

async function logDeviceMessages(request: Request, env: Env): Promise<Response> {
  try {
    const body = (await request.json()) as { logs?: unknown };
    const logs = Array.isArray(body.logs) ? body.logs : [];
    const timestamp = now();
    for (const entry of logs) {
      await env.DB.prepare("INSERT INTO device_logs (message, created_at) VALUES (?, ?)")
        .bind(String(entry), timestamp)
        .run();
    }
  } catch {
    // Logging is best-effort; never fail the device's request.
  }
  return new Response(null, { status: 200 });
}

async function pushUpdate(env: Env, serialNumber: string): Promise<PushSummary> {
  const { results } = await env.DB.prepare(
    "SELECT push_token FROM registrations WHERE serial_number = ?",
  )
    .bind(serialNumber)
    .all<{ push_token: string }>();

  const tokens = (results ?? []).map((row) => row.push_token);
  const pushResults = await pushToDevices(env, tokens);

  const stale = pushResults.filter(isStaleToken).map((r) => r.pushToken);
  for (const token of stale) {
    await env.DB.prepare(
      "DELETE FROM registrations WHERE serial_number = ? AND push_token = ?",
    )
      .bind(serialNumber, token)
      .run();
  }

  return {
    devices: tokens.length,
    delivered: pushResults.filter((r) => r.status === 200).length,
    removedStale: stale.length,
    failures: pushResults
      .filter((r) => r.status !== 200)
      .map((r) => ({ status: r.status, reason: r.reason })),
  };
}

interface PushSummary {
  devices: number;
  delivered: number;
  removedStale: number;
  failures: { status: number; reason?: string }[];
}

async function createPass(request: Request, env: Env): Promise<Response> {
  let body: {
    serialNumber?: unknown;
    authenticationToken?: unknown;
    overrides?: unknown;
  } = {};
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const serialNumber =
    typeof body.serialNumber === "string" && body.serialNumber.length > 0
      ? body.serialNumber
      : crypto.randomUUID();
  // A pass distributed as a single file (e.g. through Apple Messages for
  // Business) is signed elsewhere, so its token has to be supplied here to
  // match what was baked into that file rather than generated.
  const authenticationToken =
    typeof body.authenticationToken === "string" && body.authenticationToken.length > 0
      ? body.authenticationToken
      : randomToken();
  const overrides = JSON.stringify(body.overrides ?? {});
  const timestamp = now();

  await env.DB.prepare(
    `INSERT INTO passes (serial_number, authentication_token, overrides, updated_at, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (serial_number) DO UPDATE SET
       authentication_token = excluded.authentication_token,
       overrides = excluded.overrides,
       updated_at = excluded.updated_at`,
  )
    .bind(serialNumber, authenticationToken, overrides, timestamp, timestamp)
    .run();

  return json({ serialNumber, authenticationToken, downloadUrl: `${env.WEB_SERVICE_URL}download/${serialNumber}?token=${authenticationToken}` }, 201);
}

async function updatePass(
  request: Request,
  env: Env,
  serialNumber: string,
): Promise<Response> {
  const pass = await loadPass(env, serialNumber);
  if (!pass) return json({ error: "unknown serial number" }, 404);

  let body: { overrides?: unknown; voided?: unknown } = {};
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const overrides =
    body.overrides === undefined ? pass.overrides : JSON.stringify(body.overrides);
  const voided = body.voided === undefined ? pass.voided : body.voided ? 1 : 0;

  await env.DB.prepare(
    "UPDATE passes SET overrides = ?, voided = ?, updated_at = ? WHERE serial_number = ?",
  )
    .bind(overrides, voided, now(), serialNumber)
    .run();

  const push = await pushUpdate(env, serialNumber);
  return json({ serialNumber, push });
}

/**
 * Human-facing download link. Uses a query token rather than the ApplePass
 * header because Safari can't set headers when following a link.
 */
async function downloadPass(
  request: Request,
  env: Env,
  serialNumber: string,
): Promise<Response> {
  const token = new URL(request.url).searchParams.get("token") ?? "";
  const pass = await loadPass(env, serialNumber);
  if (!pass || !safeEqual(token, pass.authentication_token)) {
    return new Response("Unauthorized", { status: 401 });
  }

  const bytes = await buildSignedPass(env, pass);
  return new Response(bytes, {
    status: 200,
    headers: {
      "content-type": PKPASS_CONTENT_TYPE,
      "content-disposition": `attachment; filename="jonny-hq-${serialNumber}.pkpass"`,
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);
    const method = request.method.toUpperCase();

    if (segments[0] === "v1") {
      // /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}/{serialNumber}
      if (
        segments.length === 6 &&
        segments[1] === "devices" &&
        segments[3] === "registrations" &&
        segments[4] === env.PASS_TYPE_IDENTIFIER
      ) {
        const device = segments[2] as string;
        const serial = segments[5] as string;
        if (method === "POST") return registerDevice(request, env, device, serial);
        if (method === "DELETE") return unregisterDevice(request, env, device, serial);
        return new Response("Method Not Allowed", { status: 405 });
      }

      // /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}
      if (
        segments.length === 5 &&
        segments[1] === "devices" &&
        segments[3] === "registrations" &&
        segments[4] === env.PASS_TYPE_IDENTIFIER &&
        method === "GET"
      ) {
        return listUpdatedSerials(request, env, segments[2] as string);
      }

      // /v1/passes/{passTypeIdentifier}/{serialNumber}
      if (
        segments.length === 4 &&
        segments[1] === "passes" &&
        segments[2] === env.PASS_TYPE_IDENTIFIER &&
        method === "GET"
      ) {
        return getLatestPass(request, env, segments[3] as string);
      }

      // /v1/log
      if (segments.length === 2 && segments[1] === "log" && method === "POST") {
        return logDeviceMessages(request, env);
      }

      return new Response("Not Found", { status: 404 });
    }

    if (segments[0] === "download" && segments.length === 2 && method === "GET") {
      return downloadPass(request, env, segments[1] as string);
    }

    if (segments[0] === "admin") {
      if (!authorizeAdmin(request, env)) return new Response("Unauthorized", { status: 401 });

      if (segments.length === 2 && segments[1] === "passes" && method === "POST") {
        return createPass(request, env);
      }
      if (segments.length === 3 && segments[1] === "passes" && method === "PATCH") {
        return updatePass(request, env, segments[2] as string);
      }
      if (segments.length === 4 && segments[1] === "passes" && segments[3] === "push" && method === "POST") {
        return json(await pushUpdate(env, segments[2] as string));
      }
      return new Response("Not Found", { status: 404 });
    }

    if (segments.length === 0) {
      return json({ service: "jonny HQ passes", passTypeIdentifier: env.PASS_TYPE_IDENTIFIER });
    }

    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
