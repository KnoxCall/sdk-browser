// KnoxEncryptor output-format + full decrypt round-trip tests.
//
// The decrypt half implemented in this file is the ECIES INVERSE (ephemeral
// ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM), transcribed from the server
// reference implementation — src/portable-crypto/ecies.ts and
// src/portable-crypto/format.ts in the KnoxCall repo (READ-ONLY reference) —
// and NOT from the browser code under test. A successful round-trip therefore
// asserts genuine byte-compatibility with the server's kc: v1 scheme, not
// just internal self-consistency: same HKDF label, same length-prefixed info
// layout, same header-as-AAD binding, same wire segments.
//
// Runs on Node's WebCrypto (globalThis.crypto, Node >= 18).

import { describe, it, expect, beforeAll } from 'vitest';
import { KnoxEncryptor, createEncryptor, type SealingBundle, type KeyRef } from '../src/index.js';

const subtle = globalThis.crypto.subtle;

// ── constants transcribed from src/portable-crypto (server reference) ────────

const KC_PREFIX = 'kc';           // format.ts KC_PREFIX
const KC_TERMINATOR = '$';        // format.ts KC_TERMINATOR
const KC_VERSION = 1;             // format.ts KC_VERSION
const GCM_TAG_LEN = 16;           // ecies.ts GCM_TAG_LEN
const GCM_IV_LEN = 12;            // ecies.ts GCM_IV_LEN
const P256_POINT_LEN = 65;        // format.ts P256_POINT_LEN (0x04 || X || Y)
const HKDF_LABEL = 'KnoxCall-kc1-ECIES-P256-AES256GCM'; // ecies.ts HKDF_LABEL

// ArrayBuffer-backed bytes, so everything below satisfies WebCrypto's
// BufferSource under TS 5.7+ generic TypedArray typings.
type Bytes = Uint8Array<ArrayBuffer>;

const te = new TextEncoder();
const td = new TextDecoder();
const utf8 = (s: string): Bytes => te.encode(s) as Bytes;

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function b64uDecode(s: string): Bytes {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

function concatBytes(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Length-prefixed canonical HKDF info — transcribed from ecies.ts buildInfo():
// each field is prefixed with a 2-byte BE length; field order is
// label ‖ tenantId ‖ appKeyId ‖ u32be(keyVersion) ‖ datatype ‖ purpose.
function serverBuildInfo(keyRef: KeyRef, datatype: string, purpose: string): Bytes {
  const version = new Uint8Array(4);
  new DataView(version.buffer).setUint32(0, keyRef.keyVersion >>> 0, false);
  const fields: Uint8Array[] = [
    utf8(HKDF_LABEL),
    utf8(keyRef.tenantId),
    utf8(keyRef.appKeyId),
    version,
    utf8(datatype),
    utf8(purpose),
  ];
  const out: Uint8Array[] = [];
  for (const f of fields) {
    out.push(new Uint8Array([(f.length >> 8) & 0xff, f.length & 0xff]), f);
  }
  return concatBytes(...out);
}

interface KcParts {
  version: string;
  datatype: string;
  keyRefStr: string;
  ephPub: Bytes;
  iv: Bytes;
  ctTag: Bytes;
  aad: Bytes;
  segments: string[];
}

// Parse + structurally validate a kc: string, mirroring format.ts decodeKc()
// and rebuilding the AAD exactly as format.ts kcHeaderAad() does (the first
// six ':'-joined segments, UTF-8).
function splitKc(kc: string): KcParts {
  // format.ts isKc(): prefix + terminator detector.
  expect(kc.startsWith(KC_PREFIX + ':')).toBe(true);
  expect(kc.endsWith(':' + KC_TERMINATOR)).toBe(true);

  const segments = kc.split(':');
  expect(segments.length).toBe(8); // decodeKc: exactly 8 segments
  const [prefix, verStr, dt, keyRefB64, ephB64, ivB64, ctB64, term] = segments;
  expect(prefix).toBe(KC_PREFIX);
  expect(term).toBe(KC_TERMINATOR);

  // Variable segments must be padding-free base64url (format.ts b64u()).
  for (const seg of [keyRefB64, ephB64, ivB64, ctB64]) {
    expect(seg).toMatch(B64URL_RE);
  }

  const ephPub = b64uDecode(ephB64);
  const iv = b64uDecode(ivB64);
  const ctTag = b64uDecode(ctB64);
  expect(ephPub.length).toBe(P256_POINT_LEN);
  expect(ephPub[0]).toBe(0x04);
  expect(iv.length).toBe(GCM_IV_LEN);
  expect(ctTag.length).toBeGreaterThanOrEqual(GCM_TAG_LEN);

  const aad = utf8([prefix, verStr, dt, keyRefB64, ephB64, ivB64].join(':'));
  return {
    version: verStr,
    datatype: dt,
    keyRefStr: td.decode(b64uDecode(keyRefB64)),
    ephPub, iv, ctTag, aad, segments,
  };
}

function parseKeyRefStr(s: string): KeyRef {
  const [tenantId, appKeyId, kv] = s.split(':');
  return { tenantId, appKeyId, keyVersion: Number(kv) };
}

// The ECIES inverse, per ecies.ts openToBuffer(): ECDH(recipient_priv,
// eph_pub) -> HKDF-SHA256(salt=eph_pub_raw, info=buildInfo(...)) -> AES-GCM
// open with the kc header as AAD. `opts` lets tests derive the CEK under a
// deliberately-wrong context to prove the HKDF info binding.
async function decryptKc(
  kc: string,
  recipientPrivate: CryptoKey,
  opts: { purpose?: string; infoKeyRef?: KeyRef; infoDatatype?: string } = {},
): Promise<{ text: string; bytes: Uint8Array; datatype: string }> {
  const p = splitKc(kc);
  const wireKeyRef = parseKeyRefStr(p.keyRefStr);

  const ephKey = await subtle.importKey(
    'raw', p.ephPub, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const z = await subtle.deriveBits({ name: 'ECDH', public: ephKey }, recipientPrivate, 256);
  const hkdfKey = await subtle.importKey('raw', z, 'HKDF', false, ['deriveBits']);

  const info = serverBuildInfo(
    opts.infoKeyRef ?? wireKeyRef,
    opts.infoDatatype ?? p.datatype,
    opts.purpose ?? '',
  );
  const cekBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: p.ephPub, info }, hkdfKey, 256,
  );
  const cek = await subtle.importKey('raw', cekBits, { name: 'AES-GCM' }, false, ['decrypt']);

  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: p.iv, additionalData: p.aad, tagLength: 128 }, cek, p.ctTag,
  );
  const bytes = new Uint8Array(pt);
  return { text: td.decode(bytes), bytes, datatype: p.datatype };
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const KEY_REF: KeyRef = { tenantId: 'ten_0a1b2c', appKeyId: 'app_main', keyVersion: 3 };

let recipientPrivate: CryptoKey;
let otherPrivate: CryptoKey;
let bundle: SealingBundle;

beforeAll(async () => {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  recipientPrivate = kp.privateKey;
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  bundle = { public_key_raw: b64uEncode(raw), key_ref: KEY_REF };

  const other = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  otherPrivate = other.privateKey;
});

// ── output format ────────────────────────────────────────────────────────────

describe('KnoxEncryptor output format', () => {
  it('produces kc:<version>:<datatype>:<key_ref>:<eph>:<iv>:<ct||tag>:$ with valid segments', async () => {
    const enc = new KnoxEncryptor(bundle);
    const kc = await enc.encrypt('hello world');
    const p = splitKc(kc); // asserts prefix, terminator, 8 segments, b64url, lengths
    expect(p.version).toBe(String(KC_VERSION));
    expect(p.datatype).toBe('s');
    expect(kc.startsWith('kc:1:s:')).toBe(true);
  });

  it('binds the key_ref as "<tenantId>:<appKeyId>:<keyVersion>" (format.ts formatKeyRef)', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('x');
    expect(splitKc(kc).keyRefStr).toBe('ten_0a1b2c:app_main:3');
  });

  it('sizes the ciphertext segment as plaintext-length + 16-byte GCM tag', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('hello world'); // 11 bytes
    expect(splitKc(kc).ctTag.length).toBe(11 + GCM_TAG_LEN);
    const empty = await new KnoxEncryptor(bundle).encrypt('');
    expect(splitKc(empty).ctTag.length).toBe(GCM_TAG_LEN);
  });

  it('uses a fresh ephemeral key and IV for every encryption', async () => {
    const enc = new KnoxEncryptor(bundle);
    const a = splitKc(await enc.encrypt('same plaintext'));
    const b = splitKc(await enc.encrypt('same plaintext'));
    expect(b64uEncode(a.ephPub)).not.toBe(b64uEncode(b.ephPub));
    expect(b64uEncode(a.iv)).not.toBe(b64uEncode(b.iv));
    expect(a.segments[6]).not.toBe(b.segments[6]);
  });

  it('tags datatypes like the server value codec: s / n / b / j', async () => {
    const enc = new KnoxEncryptor(bundle);
    expect(splitKc(await enc.encrypt('str')).datatype).toBe('s');
    expect(splitKc(await enc.encrypt(42.5)).datatype).toBe('n');
    expect(splitKc(await enc.encrypt(false)).datatype).toBe('b');
    expect(splitKc(await enc.encrypt({ a: 1 })).datatype).toBe('j');
    expect(splitKc(await enc.encrypt([1, 2])).datatype).toBe('j');
    expect(splitKc(await enc.encrypt(null)).datatype).toBe('j');
  });
});

// ── decrypt round-trip (byte-compatibility with the server scheme) ───────────

describe('KnoxEncryptor round-trip via the server ECIES inverse', () => {
  it('round-trips a string', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('hello world');
    const out = await decryptKc(kc, recipientPrivate);
    expect(out.text).toBe('hello world');
    expect(out.datatype).toBe('s');
  });

  it('round-trips unicode text byte-for-byte', async () => {
    const value = 'Grüße 👋 — ένα μυστικό';
    const kc = await new KnoxEncryptor(bundle).encrypt(value);
    const out = await decryptKc(kc, recipientPrivate);
    expect(out.text).toBe(value);
    expect(out.bytes).toEqual(utf8(value));
  });

  it('round-trips the empty string', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('');
    expect((await decryptKc(kc, recipientPrivate)).text).toBe('');
  });

  it('round-trips numbers via the "n" codec (plaintextToValue: Number())', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt(42.5);
    const out = await decryptKc(kc, recipientPrivate);
    expect(out.datatype).toBe('n');
    expect(Number(out.text)).toBe(42.5);
  });

  it('round-trips booleans via the "b" codec', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt(true);
    const out = await decryptKc(kc, recipientPrivate);
    expect(out.datatype).toBe('b');
    expect(out.text).toBe('true');
  });

  it('round-trips JSON objects and null via the "j" codec', async () => {
    const value = { card: { last4: '4242' }, tags: ['a', 'b'], n: 7 };
    const kc = await new KnoxEncryptor(bundle).encrypt(value);
    const out = await decryptKc(kc, recipientPrivate);
    expect(out.datatype).toBe('j');
    expect(JSON.parse(out.text)).toEqual(value);

    const kcNull = await new KnoxEncryptor(bundle).encrypt(null);
    expect((await decryptKc(kcNull, recipientPrivate)).text).toBe('null');
  });

  it('round-trips a PAN-sized secret through createEncryptor()', async () => {
    const enc = createEncryptor(bundle, { purpose: 'pci' });
    expect(enc).toBeInstanceOf(KnoxEncryptor);
    const kc = await enc.encrypt('4242424242424242');
    const out = await decryptKc(kc, recipientPrivate, { purpose: 'pci' });
    expect(out.text).toBe('4242424242424242');
  });
});

// ── context binding: HKDF info + AAD (the security beat over ev:) ────────────

describe('context binding', () => {
  it('fails to decrypt under the wrong purpose (data-role pinning)', async () => {
    const kc = await new KnoxEncryptor(bundle, { purpose: 'pci' }).encrypt('secret');
    await expect(decryptKc(kc, recipientPrivate, { purpose: '' })).rejects.toThrow();
    await expect(decryptKc(kc, recipientPrivate, { purpose: 'eu' })).rejects.toThrow();
    await expect(decryptKc(kc, recipientPrivate, { purpose: 'pci' })).resolves.toBeTruthy();
  });

  it('defaults purpose to the empty string when omitted', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    await expect(decryptKc(kc, recipientPrivate, { purpose: '' })).resolves.toBeTruthy();
    await expect(decryptKc(kc, recipientPrivate, { purpose: 'pci' })).rejects.toThrow();
  });

  it('fails to decrypt with the wrong private key', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    await expect(decryptKc(kc, otherPrivate)).rejects.toThrow();
  });

  it('pins the keyVersion into the derived key (HKDF info binding)', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    await expect(decryptKc(kc, recipientPrivate, {
      infoKeyRef: { ...KEY_REF, keyVersion: 4 },
    })).rejects.toThrow();
  });

  it('pins tenantId and appKeyId into the derived key', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    await expect(decryptKc(kc, recipientPrivate, {
      infoKeyRef: { ...KEY_REF, tenantId: 'ten_other' },
    })).rejects.toThrow();
    await expect(decryptKc(kc, recipientPrivate, {
      infoKeyRef: { ...KEY_REF, appKeyId: 'app_other' },
    })).rejects.toThrow();
  });

  it('authenticates the header as AAD: tampering with the version segment breaks the tag', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    // The version is in the AAD but NOT in the HKDF info, so this isolates
    // the header-as-AAD binding from the key derivation.
    const tampered = kc.replace(/^kc:1:/, 'kc:2:');
    expect(tampered).not.toBe(kc);
    await expect(decryptKc(tampered, recipientPrivate)).rejects.toThrow();
  });

  it('rejects a flipped ciphertext bit', async () => {
    const kc = await new KnoxEncryptor(bundle).encrypt('secret');
    const segments = kc.split(':');
    const ct = b64uDecode(segments[6]);
    ct[0] ^= 0x01;
    segments[6] = b64uEncode(ct);
    await expect(decryptKc(segments.join(':'), recipientPrivate)).rejects.toThrow();
  });

  it('length-prefixed info layout matches the server reference exactly', () => {
    // Spot-check the transcription itself so a drive-by edit to the test
    // helper can't silently weaken the byte-compat assertion.
    const info = serverBuildInfo({ tenantId: 'ab', appKeyId: 'c', keyVersion: 258 }, 's', 'p');
    const expected = concatBytes(
      new Uint8Array([0, 33]), utf8(HKDF_LABEL),          // label (33 bytes)
      new Uint8Array([0, 2]), utf8('ab'),                 // tenantId
      new Uint8Array([0, 1]), utf8('c'),                  // appKeyId
      new Uint8Array([0, 4]), new Uint8Array([0, 0, 1, 2]), // u32be(258)
      new Uint8Array([0, 1]), utf8('s'),                  // datatype
      new Uint8Array([0, 1]), utf8('p'),                  // purpose
    );
    expect(info).toEqual(expected);
  });
});

// ── input validation ─────────────────────────────────────────────────────────

describe('KnoxEncryptor input validation', () => {
  it('rejects a public key that is not 65 bytes', () => {
    const short = { ...bundle, public_key_raw: b64uEncode(new Uint8Array(64).fill(4)) };
    expect(() => new KnoxEncryptor(short)).toThrow(/65-byte/);
    const long = { ...bundle, public_key_raw: b64uEncode(new Uint8Array(66).fill(4)) };
    expect(() => new KnoxEncryptor(long)).toThrow(/65-byte/);
  });

  it('rejects a 65-byte key without the uncompressed-point 0x04 prefix', () => {
    const raw = b64uDecode(bundle.public_key_raw);
    const bad = new Uint8Array(raw);
    bad[0] = 0x02; // compressed-point marker
    expect(() => new KnoxEncryptor({ ...bundle, public_key_raw: b64uEncode(bad) })).toThrow(/65-byte/);
  });

  it('rejects non-finite numbers', async () => {
    const enc = new KnoxEncryptor(bundle);
    await expect(enc.encrypt(NaN)).rejects.toThrow(/non-finite/);
    await expect(enc.encrypt(Infinity)).rejects.toThrow(/non-finite/);
    await expect(enc.encrypt(-Infinity)).rejects.toThrow(/non-finite/);
  });

  it('rejects unencryptable value types', async () => {
    const enc = new KnoxEncryptor(bundle);
    await expect(enc.encrypt(undefined)).rejects.toThrow(/cannot encrypt/);
    await expect(enc.encrypt(() => 'x')).rejects.toThrow(/cannot encrypt/);
    await expect(enc.encrypt(Symbol('x'))).rejects.toThrow(/cannot encrypt/);
    await expect(enc.encrypt(10n as unknown)).rejects.toThrow(/cannot encrypt/);
  });
});
