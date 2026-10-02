// @knoxcall/browser — client-side encryption for the browser.
//
// Seals a value into a portable `kc:` ciphertext IN THE PAGE, using the
// tenant's public key, so plaintext (a PAN, an SSN) never touches your
// servers. The resulting `kc:` string is byte-compatible with KnoxCall's
// server-side format (src/portable-crypto): KnoxCall — and only KnoxCall,
// holding the private key — can decrypt it.
//
// No API key is ever shipped to the browser. Your backend fetches the sealing
// bundle (GET /v1/encrypt/sealing-bundle) with its API key and hands the
// public bits to the page; encryption is then a pure client-side operation
// with no network round-trip.
//
// Scheme (must match src/portable-crypto/ecies.ts exactly): ephemeral
// ECDH P-256 -> HKDF-SHA256(salt=ephemeral_pubkey, info=context) -> AES-256-GCM,
// with the kc: header bound as GCM additional-authenticated-data.

const LABEL = 'KnoxCall-kc1-ECIES-P256-AES256GCM';
const KC_VERSION = 1;

// WebCrypto is `globalThis.crypto.subtle` in browsers and Node >= 20. Access
// via `any` so this file typechecks without a DOM lib dependency.
const g: any = globalThis as any;
const subtle: any = g.crypto.subtle;

export interface KeyRef {
  tenantId: string;
  appKeyId: string;
  keyVersion: number;
}

export interface SealingBundle {
  // Recipient (tenant app) ECDH P-256 public key as a base64url-encoded
  // 65-byte uncompressed point (0x04 || X || Y) — as returned by
  // GET /v1/encrypt/sealing-bundle (public_key_raw).
  public_key_raw: string;
  key_ref: KeyRef;
}

export interface KnoxEncryptorOptions {
  // Optional data-role bound into every ciphertext (e.g. "pci", "eu"). The
  // same role must be supplied to decrypt.
  purpose?: string;
}

type DataType = 's' | 'n' | 'b' | 'j';

// ─── byte helpers (browser + Node safe; no Buffer, no DOM types) ─────────────

const te = new TextEncoder();

function utf8(s: string): Uint8Array {
  return te.encode(s);
}

function b64u(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64: string = g.btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64u(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin: string = g.atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function u16be(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

// Length-prefixed canonical HKDF info — MUST byte-match server buildInfo().
function buildInfo(keyRef: KeyRef, datatype: DataType, purpose: string): Uint8Array {
  const fields: Uint8Array[] = [
    utf8(LABEL),
    utf8(keyRef.tenantId),
    utf8(keyRef.appKeyId),
    u32be(keyRef.keyVersion >>> 0),
    utf8(datatype),
    utf8(purpose),
  ];
  const parts: Uint8Array[] = [];
  for (const f of fields) { parts.push(u16be(f.length)); parts.push(f); }
  return concat(...parts);
}

function valueToPlaintext(v: unknown): { bytes: Uint8Array; datatype: DataType } {
  switch (typeof v) {
    case 'string': return { bytes: utf8(v), datatype: 's' };
    case 'number':
      if (!Number.isFinite(v)) throw new Error('cannot encrypt non-finite number');
      return { bytes: utf8(String(v)), datatype: 'n' };
    case 'boolean': return { bytes: utf8(v ? 'true' : 'false'), datatype: 'b' };
    case 'object':
      if (v === null) return { bytes: utf8('null'), datatype: 'j' };
      return { bytes: utf8(JSON.stringify(v)), datatype: 'j' };
    default:
      throw new Error(`cannot encrypt value of type ${typeof v}`);
  }
}

export class KnoxEncryptor {
  private readonly keyRef: KeyRef;
  private readonly publicKeyRaw: Uint8Array;
  private readonly purpose: string;

  constructor(bundle: SealingBundle, opts: KnoxEncryptorOptions = {}) {
    this.keyRef = bundle.key_ref;
    this.publicKeyRaw = unb64u(bundle.public_key_raw);
    if (this.publicKeyRaw.length !== 65 || this.publicKeyRaw[0] !== 0x04) {
      throw new Error('public_key_raw must be a base64url 65-byte uncompressed P-256 point');
    }
    this.purpose = opts.purpose ?? '';
  }

  // Seal a value into a kc: ciphertext string. Pure client-side; no network.
  async encrypt(value: unknown): Promise<string> {
    const { bytes, datatype } = valueToPlaintext(value);

    const recipient = await subtle.importKey(
      'raw', this.publicKeyRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const ephPubRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));

    // Z = ECDH shared secret (P-256 X coordinate, 32 bytes).
    const z = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256));

    const hkdfKey = await subtle.importKey('raw', z, 'HKDF', false, ['deriveBits']);
    const info = buildInfo(this.keyRef, datatype, this.purpose);
    const cekBits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ephPubRaw, info }, hkdfKey, 256);
    const cekKey = await subtle.importKey('raw', cekBits, { name: 'AES-GCM' }, false, ['encrypt']);

    const iv = g.crypto.getRandomValues(new Uint8Array(12));
    const keyRefStr = `${this.keyRef.tenantId}:${this.keyRef.appKeyId}:${this.keyRef.keyVersion}`;
    const header = ['kc', String(KC_VERSION), datatype, b64u(utf8(keyRefStr)), b64u(ephPubRaw), b64u(iv)].join(':');
    const aad = utf8(header);

    const ctTag = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, cekKey, bytes,
    ));

    return `kc:${KC_VERSION}:${datatype}:${b64u(utf8(keyRefStr))}:${b64u(ephPubRaw)}:${b64u(iv)}:${b64u(ctTag)}:$`;
  }
}

// Convenience: build an encryptor from a fetched sealing bundle.
export function createEncryptor(bundle: SealingBundle, opts?: KnoxEncryptorOptions): KnoxEncryptor {
  return new KnoxEncryptor(bundle, opts);
}

export { KnoxClient, type KnoxClientOptions } from './client.js';
export * from './elements.js';
export * from './secure-field.js';
