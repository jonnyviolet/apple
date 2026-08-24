import type { Env } from "./env";

interface CachedToken {
  jwt: string;
  issuedAt: number;
}

// APNs rejects tokens older than an hour and throttles regeneration, so the
// JWT is reused across pushes within a single isolate.
let cached: CachedToken | null = null;

function base64Url(input: string | Uint8Array): string {
  const binary =
    typeof input === "string"
      ? input
      : Array.from(input, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToPkcs8(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function providerToken(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cached && now - cached.issuedAt < 45 * 60) return cached.jwt;

  const header = base64Url(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID }));
  const claims = base64Url(JSON.stringify({ iss: env.TEAM_IDENTIFIER, iat: now }));
  const message = `${header}.${claims}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToPkcs8(env.APNS_KEY_P8),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(message),
  );

  const jwt = `${message}.${base64Url(new Uint8Array(signature))}`;
  cached = { jwt, issuedAt: now };
  return jwt;
}

export interface PushResult {
  pushToken: string;
  status: number;
  reason?: string;
}

/**
 * Wallet update pushes carry no payload: the notification is purely a signal
 * for the device to call back into GET /v1/devices/... and fetch what changed.
 */
export async function pushToDevices(env: Env, pushTokens: string[]): Promise<PushResult[]> {
  if (pushTokens.length === 0) return [];
  const jwt = await providerToken(env);

  return Promise.all(
    pushTokens.map(async (pushToken): Promise<PushResult> => {
      let response: Response;
      try {
        response = await fetch(`https://${env.APNS_HOST}/3/device/${pushToken}`, {
          method: "POST",
          headers: {
            authorization: `bearer ${jwt}`,
            "apns-topic": env.PASS_TYPE_IDENTIFIER,
            "apns-push-type": "background",
            "apns-priority": "5",
            "content-type": "application/json",
          },
          body: "{}",
        });
      } catch (error) {
        // The pass has already been updated in D1 at this point, so a transport
        // failure must not fail the caller: the device still picks the change up
        // on its next poll. APNs is HTTP/2-only, which is why this always fails
        // under `wrangler dev` local mode.
        return {
          pushToken,
          status: 0,
          reason: error instanceof Error ? error.message : "fetch failed",
        };
      }

      if (response.status === 200) return { pushToken, status: 200 };

      let reason: string | undefined;
      try {
        const body = (await response.json()) as { reason?: string };
        reason = body.reason;
      } catch {
        reason = await response.text();
      }
      return { pushToken, status: response.status, reason };
    }),
  );
}

/** APNs reports tokens that no longer belong to an installed pass. */
export function isStaleToken(result: PushResult): boolean {
  return (
    result.status === 410 ||
    result.reason === "BadDeviceToken" ||
    result.reason === "Unregistered"
  );
}
