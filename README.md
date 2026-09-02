# jonny HQ passes

Apple Wallet pass web service for `pass.to.jonny`, running as a Cloudflare Worker at
`passes.jonny.to`. It signs `.pkpass` files on demand, implements the five PassKit
web service endpoints Wallet calls, and pushes update notifications through APNs.

Pass Designer builds the *design*; it has no field for `webServiceURL`,
`authenticationToken` or `serialNumber` because those are per-pass issuance values.
This service supplies them: `template/pass.json` holds the design, and every pass is
signed with its own serial number and token at request time.

## How updates actually work

1. You change a pass: `PATCH /admin/passes/{serial}`.
2. The Worker bumps `updated_at` and sends an **empty** APNs push (`{}`) to every
   device registered for that serial, with `apns-topic` set to the pass type
   identifier. The push carries no content — it's only a "come look" signal.
3. The device calls `GET /v1/devices/.../registrations/...` to ask which serials
   changed, then `GET /v1/passes/{passTypeId}/{serial}` to download the new pass.
4. Wallet shows a lock-screen notification only for fields that declare a
   `changeMessage` (e.g. `"changeMessage": "now %@"`). Everything else updates silently.

## Setup

### 1. Assets

Replace the placeholders in `template/` with your real Pass Designer exports:

```
template/icon.png       29x29    (required — Pass Designer doesn't emit this one)
template/icon@2x.png    58x58
template/icon@3x.png    87x87
template/strip@3x.png   1125x432
```

`template/pass.json` is the design. Don't put `serialNumber`, `authenticationToken`
or `webServiceURL` in it — the Worker overwrites them per pass.

### 2. Certificates

Pass signing certificate, exported from Keychain Access as a `.p12`:

```bash
base64 -i PassCert.p12 | tr -d '\n' | npx wrangler secret put PASS_CERT_P12_BASE64
npx wrangler secret put PASS_CERT_P12_PASSWORD
```

Apple WWDR G4 intermediate:

```bash
curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer
openssl x509 -inform DER -in AppleWWDRCAG4.cer -out AppleWWDRCAG4.pem
npx wrangler secret put WWDR_CERT_PEM < AppleWWDRCAG4.pem
```

### 3. APNs key

Workers cannot do client-certificate mTLS, so APNs auth must be **token-based**.
Create an APNs Auth Key (`.p8`) in the developer portal — one key covers every topic
your team owns, including `pass.to.jonny`.

```bash
npx wrangler secret put APNS_KEY_P8 < AuthKey_XXXXXXXXXX.p8
npx wrangler secret put APNS_KEY_ID     # the 10-character key ID
npx wrangler secret put ADMIN_TOKEN     # openssl rand -hex 32
```

### 4. Database and deploy

```bash
npx wrangler d1 create passes     # paste database_id into wrangler.toml
npm run db:init
npm run deploy
```

Point `passes.jonny.to` at the Worker as a custom domain (already declared in
`wrangler.toml`). Using a subdomain keeps the fixed `/v1/*` PassKit paths off the
apex domain serving the site.

## Issuing a pass

```bash
curl -X POST https://passes.jonny.to/admin/passes \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"serialNumber": "0001"}'
```

Returns a `downloadUrl`; open it on an iPhone and Wallet offers to add the pass.
Each pass gets its own random `authenticationToken` — a shared token would let any
holder fetch everyone else's pass.

## Distributing one shared pass (Apple Messages for Business)

AMB uploads a single `.pkpass` file, so every recipient gets the same
`serialNumber` and `authenticationToken`. That works — one push updates every
holder — but there is no per-person state: you can't personalise or revoke
individually.

In this mode Pass Designer signs the file you distribute, and the Worker only
serves updates. Add the three keys to the Pass Designer template's `pass.json`,
export, and upload that file to AMB. Then tell the Worker about the serial so it
recognises the token the file carries:

```bash
curl -X POST https://passes.jonny.to/admin/passes \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"serialNumber": "0001", "authenticationToken": "<same token as in pass.json>"}'
```

The signing certificate is still required even though Pass Designer signs the
distributed file: `GET /v1/passes/...` returns a whole new signed pass, because
that is how Wallet applies an update.

## Announcing something to every holder

The `announcement` auxiliary field carries `"changeMessage": "%@"`, so writing
a new value into it both updates the pass and raises a lock-screen notification
reading exactly that value.

The everyday way to do this is <https://passes.jonny.to/send>: type the message,
press send. The page is public but does nothing until you enter `ADMIN_TOKEN`,
which the browser then remembers, and it drives three endpoints:

- `GET /send/state` — current announcement text and how many devices are registered
- `POST /send/announce` — `{"message": "..."}`, writes the field and pushes
- `POST /send/clear` — blanks the field, see below

All take `Authorization: Bearer $ADMIN_TOKEN`, and all act on
`SHARED_SERIAL_NUMBER`. The announce equivalent by hand:

```bash
curl -X PATCH https://passes.jonny.to/admin/passes/0001 \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"overrides": {"eventTicket": {"auxiliaryFields": [
        {"key": "announcement", "value": "new song out now"}]}}}'
```

A notification only fires when the value actually changes, so sending the same
text twice is silent the second time.

### Clearing it again

`POST /send/clear` blanks the field without pushing and without touching
`updated_at` — either would make Wallet notify a second time, with empty text.
So a clear is stored for newly served passes, while existing holders keep the
last announcement until the next one replaces it.

## Updating a pass

`overrides` is deep-merged onto `template/pass.json`. Field arrays merge by `key`,
so you only name what changes:

```bash
curl -X PATCH https://passes.jonny.to/admin/passes/0001 \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"overrides": {"eventTicket": {"primaryFields": [
        {"key": "bling", "value": "✨✨✨", "changeMessage": "now %@"}]}}}'
```

The response reports the push outcome per device:

```json
{"serialNumber":"0001","push":{"devices":2,"delivered":2,"removedStale":0,"failures":[]}}
```

Tokens APNs reports as `410`/`BadDeviceToken`/`Unregistered` are deleted automatically.

### The 50-subrequest ceiling

A Worker invocation on the free plan may make 50 outbound requests, and one APNs
push is one request — so a send to more than ~50 holders would silently stop at
50 with `Too many subrequests`. Pushes are therefore fanned out in batches of 20
through `POST /internal/push-batch`, called over a service binding to this same
Worker, so each batch gets its own budget and stays within the CPU-time limit.
The dispatching invocation spends one request per batch and another for a retry,
which puts the ceiling at roughly 50 batches (about 1,000 holders) before retry
overhead; past that, batches would need to fan out a second level.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/devices/{deviceId}/registrations/{passTypeId}/{serial}` | Device registers for updates |
| DELETE | `/v1/devices/{deviceId}/registrations/{passTypeId}/{serial}` | Device unregisters |
| GET | `/v1/devices/{deviceId}/registrations/{passTypeId}` | Which serials changed |
| GET | `/v1/passes/{passTypeId}/{serial}` | Download the current pass |
| POST | `/v1/log` | Device error log, stored in `device_logs` |
| GET | `/download/{serial}?token=` | Human-facing download link |
| POST | `/admin/passes` | Issue a pass |
| PATCH | `/admin/passes/{serial}` | Update a pass and push |
| POST | `/admin/passes/{serial}/push` | Re-push without changing anything |
| POST | `/internal/push-batch` | One batch of pushes, called by the Worker itself |

`/v1/*` uses `Authorization: ApplePass <authenticationToken>`; `/admin/*` uses
`Authorization: Bearer <ADMIN_TOKEN>`.

## Local development

```bash
cp .dev.vars.example .dev.vars   # fill in
npm run db:init:local
npm run dev
```

**APNs pushes cannot be tested locally.** APNs is HTTP/2-only and Miniflare's fetch
speaks HTTP/1.1, so every push fails with `Network connection lost` under
`wrangler dev`. Everything else — signing, registration, the update poll — works
locally. Test pushes against a deployed Worker.

## Debugging

`device_logs` is the first place to look when Wallet rejects a pass:

```bash
npx wrangler d1 execute passes --remote \
  --command "SELECT * FROM device_logs ORDER BY id DESC LIMIT 20"
```

Also useful: Console.app on a Mac with the iPhone connected, filtered to `passd`.
