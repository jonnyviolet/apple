import forge from "node-forge";
import { zipSync } from "fflate";
import type { Env, PassRecord } from "./env";
import { ASSETS } from "./assets";
import template from "../template/pass.json";

type Json = Record<string, unknown>;

// `noUncheckedIndexedAccess` widens forge's oid lookups to `string | undefined`.
function oid(name: string): string {
  const value = forge.pki.oids[name];
  if (!value) throw new Error(`Unknown OID: ${name}`);
  return value;
}

/**
 * Deep merge used to apply per-pass overrides onto the design template.
 * Arrays of pass fields are merged by their `key` so an override only has to
 * name the field it changes:
 *   { "eventTicket": { "primaryFields": [{ "key": "bling", "value": "***" }] } }
 */
function merge(base: unknown, patch: unknown): unknown {
  if (Array.isArray(base) && Array.isArray(patch)) {
    const keyed = base.every((e) => isFieldObject(e)) && patch.every((e) => isFieldObject(e));
    if (!keyed) return patch;
    const out = base.map((e) => ({ ...(e as Json) }));
    for (const entry of patch as Json[]) {
      const idx = out.findIndex((e) => e["key"] === entry["key"]);
      if (idx === -1) out.push({ ...entry });
      else out[idx] = merge(out[idx], entry) as Json;
    }
    return out;
  }
  if (isPlainObject(base) && isPlainObject(patch)) {
    const out: Json = { ...base };
    for (const [k, v] of Object.entries(patch)) {
      out[k] = k in base ? merge(base[k], v) : v;
    }
    return out;
  }
  return patch;
}

function isPlainObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFieldObject(value: unknown): boolean {
  return isPlainObject(value) && typeof value["key"] === "string";
}

export function buildPassJson(env: Env, pass: PassRecord): string {
  let overrides: Json = {};
  try {
    const parsed: unknown = JSON.parse(pass.overrides || "{}");
    if (isPlainObject(parsed)) overrides = parsed;
  } catch {
    // A malformed override shouldn't take the whole pass down; ship the template.
  }

  const merged = merge(template as unknown as Json, overrides) as Json;

  merged["passTypeIdentifier"] = env.PASS_TYPE_IDENTIFIER;
  merged["teamIdentifier"] = env.TEAM_IDENTIFIER;
  merged["serialNumber"] = pass.serial_number;
  merged["authenticationToken"] = pass.authentication_token;
  merged["webServiceURL"] = env.WEB_SERVICE_URL;
  if (pass.voided) merged["voided"] = true;

  return JSON.stringify(merged);
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const view = new Uint8Array(bytes);
  const digest = await crypto.subtle.digest("SHA-1", view);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function binaryStringToBytes(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i) & 0xff;
  return out;
}

interface SigningMaterial {
  certificate: forge.pki.Certificate;
  privateKey: forge.pki.PrivateKey;
  wwdr: forge.pki.Certificate;
}

function loadSigningMaterial(env: Env): SigningMaterial {
  const der = forge.util.decode64(env.PASS_CERT_P12_BASE64);
  const p12Asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, env.PASS_CERT_P12_PASSWORD);

  let certificate: forge.pki.Certificate | undefined;
  let privateKey: forge.pki.PrivateKey | undefined;

  for (const safeContents of p12.safeContents) {
    for (const bag of safeContents.safeBags) {
      if (bag.type === forge.pki.oids.certBag && bag.cert) {
        // The Pass Type ID leaf is the one with a matching common name;
        // a .p12 export often bundles the WWDR intermediate alongside it.
        const cn = bag.cert.subject.getField("CN");
        if (cn && typeof cn.value === "string" && cn.value.startsWith("Pass Type ID:")) {
          certificate = bag.cert;
        } else if (!certificate) {
          certificate = bag.cert;
        }
      }
      const key = bag.key ?? null;
      if (key && (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag)) {
        privateKey = key;
      }
    }
  }

  if (!certificate) throw new Error("No certificate found in PASS_CERT_P12_BASE64");
  if (!privateKey) throw new Error("No private key found in PASS_CERT_P12_BASE64");

  const wwdr = forge.pki.certificateFromPem(env.WWDR_CERT_PEM);
  return { certificate, privateKey, wwdr };
}

/**
 * Detached CMS/PKCS#7 signature over manifest.json, which is what Wallet
 * validates. WebCrypto can't produce CMS, hence node-forge.
 */
function signManifest(env: Env, manifest: string): Uint8Array {
  const { certificate, privateKey, wwdr } = loadSigningMaterial(env);

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifest, "utf8");
  p7.addCertificate(certificate);
  p7.addCertificate(wwdr);
  p7.addSigner({
    key: privateKey as forge.pki.rsa.PrivateKey,
    certificate,
    digestAlgorithm: oid("sha256"),
    authenticatedAttributes: [
      { type: oid("contentType"), value: oid("data") },
      { type: oid("messageDigest") },
      { type: oid("signingTime"), value: new Date().toISOString() },
    ],
  });
  p7.sign({ detached: true });

  return binaryStringToBytes(forge.asn1.toDer(p7.toAsn1()).getBytes());
}

export async function buildSignedPass(env: Env, pass: PassRecord): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const files: Record<string, Uint8Array> = {};

  for (const [name, bytes] of Object.entries(ASSETS)) {
    files[name] = new Uint8Array(bytes);
  }
  files["pass.json"] = encoder.encode(buildPassJson(env, pass));

  const manifest: Record<string, string> = {};
  for (const name of Object.keys(files).sort()) {
    manifest[name] = await sha1Hex(files[name] as Uint8Array);
  }
  const manifestJson = JSON.stringify(manifest);

  files["manifest.json"] = encoder.encode(manifestJson);
  files["signature"] = signManifest(env, manifestJson);

  return zipSync(files, { level: 6 });
}
