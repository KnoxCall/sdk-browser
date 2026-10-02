# @knoxcall/browser

Everything KnoxCall does **inside a browser**, in one dependency-free package:

| Export | What it does |
| --- | --- |
| `mountSecureField` | **Hosted fields.** Mounts a KnoxCall-served iframe that captures a sensitive value and exchanges it for a **vault token**. The value never enters your page's JavaScript, your bundle, or your backend. |
| `KnoxClient` | Reveal a value in the browser with a **single-use capability token** (`kct_…`) — decrypt a `kc:` ciphertext or detokenize a vault token — or tokenize one directly. No API key involved. |
| `KnoxEncryptor` / `createEncryptor` | Client-side ECIES sealing (P-256 → HKDF-SHA256 → AES-256-GCM) into a portable `kc:` ciphertext. No network round-trip. |
| `parseKnoxMessage`, `isTrustedElementOrigin`, `KNOX_MESSAGE` | The framework-agnostic iframe `postMessage` protocol the hosted fields speak (also used by [`@knoxcall/react`](https://www.npmjs.com/package/@knoxcall/react)). |

KnoxCall holds no PCI DSS attestation and nothing in this package is a
compliance control; what the hosted fields change is *where the plaintext
exists*. Card (`pan`) vaults are refused for browser capture today — see
[Card fields](#card-fields-are-not-available-yet).

## Install

```sh
npm install @knoxcall/browser@^0.1.0
```

Requires WebCrypto (`globalThis.crypto.subtle`) for `KnoxEncryptor`: any modern
browser, or Node ≥ 18 for SSR/tests. `mountSecureField` and `KnoxClient` need
neither.

---

## Hosted fields

A hosted field is a cross-origin iframe served from
`https://elements.knoxcall.com`. The customer types into **our** document; your
page gets a `complete` boolean while they type and a **vault token** when you
ask for one. There is no long-lived secret in the page: the credential is a
single-use capability token your backend mints, bound to one vault and to the
exact page origins it may be presented from, and it expires in five minutes.

### 1. Your backend mints a capability token

```ts
// Your backend, with your ordinary KnoxCall credentials.
// POST /v1/client-tokens
app.post('/api/field-token', async (_req, res) => {
  res.json(await knox.crypto.mintClientToken({
    action: 'tokenize',
    vault: 'customer-ssn',                 // the ONE vault this may write into
    origins: ['https://shop.example.com'], // exact origins, no wildcards
    // ttl_seconds: 300 (default; 600 max)
  }));
  // -> { token: "kct_…", expires_at, action, vault_id, origins }
});
```

`origins` are **exact** `https://host[:port]` strings. Wildcards are not
supported in any spelling: a suffix wildcard binds the capability to every
current and future subdomain, including ones you do not control yet, and
subdomain takeover is the usual way an attacker gets script execution on an
origin a company believes it owns. List each origin, or mint per page — minting
is a backend call you already make for every capture.

### 2. Your page mounts the field

```ts
import { mountSecureField } from '@knoxcall/browser';

const { token } = await fetch('/api/field-token', { method: 'POST' }).then((r) => r.json());

const field = mountSecureField(document.getElementById('ssn')!, {
  format: 'ssn',
  capabilityToken: token,
  onChange: ({ complete }) => { submitButton.disabled = !complete; },
  onToken: ({ token: vaultToken, id }) => {
    // Store `vaultToken`. It is what /v1/proxy resolves later.
    form.vaultToken.value = vaultToken;
  },
  onError: ({ code, message }) => showError(message),
});

submitButton.addEventListener('click', () => field.tokenize());
```

`mountSecureField` returns `{ tokenize(), setStyle(style), destroy(), on(event, cb), iframe }`.
`on()` returns an unsubscribe function; `destroy()` removes the iframe and its
message listener.

### Formats

`format` chooses which inputs the iframe renders. It is a **UI hint** — the
vault's real format is what the server enforces at capture, and your page cannot
influence it.

| `format` | Inputs | Validation in the iframe |
| --- | --- | --- |
| `ssn` | SSN / ITIN | 9 digits; refuses area `000`/`666`, group `00`, serial `0000`. `9xx` (ITIN) is accepted. |
| `bank_account` | routing + account | ABA 3-7-1 checksum on the routing number; 4–17 digits of account. The routing number rides along as `metadata.routing_number` — it identifies the bank, not the account. |
| `email` | email address | RFC-shape, ≤ 254 characters. |
| `generic` | one free-text input | non-empty. |
| `pan` | number, expiry, CVC | Luhn, length and CVC length by brand, real issuer ranges, expiry not in the past. **Refused at capture — see below.** |

### Styling

The iframe is ours, so a stylesheet cannot reach into it. Pass a constrained
style object instead — an allowlist of property names, each with a value
grammar:

```ts
mountSecureField(el, {
  format: 'generic',
  capabilityToken: token,
  style: {
    color: '#111827',          // hex colours only
    backgroundColor: '#ffffff',
    borderColor: '#d1d5db',
    borderRadius: '6px',       // px / rem / em, ≤ 3 digits
    borderWidth: '1px',
    fontSize: '15px',
    fontFamily: 'system',      // a NAME: system | sans | serif | mono
    lineHeight: '1.4',
    padding: '10px 12px',
    labelColor: '#374151',
    placeholderColor: '#9ca3af',
    errorColor: '#b42318',
  },
});
```

Anything outside that grammar is **dropped silently** — no class names, no
arbitrary CSS, no `url()`. That is deliberate: CSS attribute selectors driving a
background image are a published way to read an input's value one character at a
time, so the one thing a hosted field must never accept from its parent is free
CSS.

### Card fields are not available yet

`format: 'pan'` renders and validates, but capturing into a card vault is
**refused server-side**: `POST /v1/client/tokenize` answers
`403 card_program_unavailable`, which arrives as
`onError({ code: 'card_program_unavailable' })`. KnoxCall holds no attestation
covering card data, and the gate reads the attestation document rather than a
flag, so it opens by itself when one is filed and closes by itself if one
lapses. Use the non-card formats today.

---

## Elements protocol

If you are wiring the iframe up by hand — use `mountSecureField` or
[`@knoxcall/react`](https://www.npmjs.com/package/@knoxcall/react) if you can — these are the messages:

| Direction | Type | Payload |
| --- | --- | --- |
| parent → iframe | `knox:tokenize` | — · ask the field to tokenize what the customer typed |
| parent → iframe | `knox:style` | `{ style }` · the constrained style object |
| iframe → parent | `knox:ready` | `{ format }` · the field rendered |
| iframe → parent | `knox:change` | `{ complete, brand?, last4? }` · input validity |
| iframe → parent | `knox:token` | `{ token, id, expires_at, last4?, brand?, exp_month?, exp_year? }` · the **vault token**, never the value |
| iframe → parent | `knox:error` | `{ code, message }` |

`code` is one of `incomplete`, `invalid_token`, `origin_required`,
`card_program_unavailable`, `tokenize_failed`, `network_error`,
`session_expired` — a closed set, so you can branch on it exhaustively.

Every inbound message must pass **three** gates, and each is bypassable alone:

```ts
import { parseKnoxMessage, isTrustedElementOrigin, DEFAULT_ELEMENT_ORIGINS } from '@knoxcall/browser';

window.addEventListener('message', (e) => {
  if (!isTrustedElementOrigin(e.origin, DEFAULT_ELEMENT_ORIGINS)) return; // 1. exact origin
  if (e.source !== iframe.contentWindow) return;                          // 2. OUR iframe's window
  const msg = parseKnoxMessage(e.data);                                   // 3. strict shape
  if (!msg) return;
  // ... act on msg
});
```

1. **Exact origin.** `isTrustedElementOrigin` is a string equality test — no
   prefix, suffix or pattern semantics — so `https://elements.knoxcall.com.evil.com`
   never passes.
2. **Our window.** An origin check cannot see a *different window at the same
   origin*, which is exactly what script injected into your own checkout is.
3. **Strict shape.** `parseKnoxMessage` returns `null` for anything that is not
   a well-formed message the iframe may send, rebuilds the result from validated
   primitives, and refuses the parent→iframe types outright — so a page that
   echoes our protocol back at you reaches nothing. A `knox:token` with no
   `token` is refused rather than delivered as `undefined`.

Outbound messages must carry an explicit `targetOrigin`, never `'*'`: a parent
can navigate itself between your `knox:tokenize` and the iframe's `knox:token`,
and `'*'` would deliver the token to whatever document arrived in the meantime.

If you override `elementBase` (a staging environment, a self-hosted install) you
**must** override `origins` to match, or every message from your own iframe is
discarded and the field never reports ready. The default does not widen itself
to follow `elementBase` on purpose.

---

## Reveal, and direct tokenize

Reading a value back in the browser never uses an API key. Your backend mints a
**single-use, payload-pinned** capability token bound to the exact ciphertext or
vault token, and hands only that token to the page:

```ts
// Your backend: mint a capability token bound to one ciphertext.
app.post('/api/reveal-token', async (req, res) => {
  res.json(await knox.crypto.mintClientToken({ action: 'decrypt', data: storedCiphertext }));
});
```

```ts
// Browser:
import { KnoxClient } from '@knoxcall/browser';

const { token } = await fetch('/api/reveal-token', { method: 'POST' }).then((r) => r.json());
const knox = new KnoxClient(); // optionally { baseUrl, fetchImpl }

const value = await knox.reveal(token, storedCiphertext);      // POST /v1/client/decrypt
const raw   = await knox.detokenize(token, 'tok_abc123');      // POST /v1/client/detokenize
```

`KnoxClient.tokenize(token, value)` is the same exchange in the other direction
— it is what the hosted-fields iframe calls internally. **Calling it from your
own page puts the value in your page's JavaScript**, which is the one thing the
iframe exists to prevent; use it only where the value is already in your page
for another reason.

The token is consumed server-side on first use; replaying it fails.
`KnoxClient` refuses anything that is not a `kct_…` token before making a
network call, so an API key pasted into the browser by mistake never leaves the
page.

---

## Sealing a value in the page (`kc:` ciphertexts)

An older, lower-level primitive: encrypt a value with your tenant's **public**
key so your servers only ever hold a ciphertext. The plaintext is still in your
page's JavaScript while this runs — if that matters, use a hosted field instead.

```ts
// 1. Your backend exposes the public sealing bundle.
app.get('/api/sealing-bundle', async (_req, res) => {
  res.json(await knox.crypto.getSealingBundle()); // GET /v1/encrypt/sealing-bundle
});
```

```ts
// 2. Browser:
import { createEncryptor } from '@knoxcall/browser';

const bundle = await fetch('/api/sealing-bundle').then((r) => r.json());
const encryptor = createEncryptor(bundle, { purpose: 'customer-pii' });

const ciphertext = await encryptor.encrypt('123-45-6789');
// -> "kc:1:s:<key_ref>:<eph_pubkey>:<iv>:<ct||tag>:$"
```

`encrypt()` accepts strings, finite numbers, booleans, `null`, and
JSON-serializable objects/arrays; the original type is preserved through
decryption (structure-preserving `s`/`n`/`b`/`j` datatype tags).

---

## Security model

- **No API key in the browser.** A hosted field's credential is a single-use
  `kct_` capability token minted by *your* backend, bound to one vault and to
  the exact origins it may be used from, valid for five minutes.
- **The value leaves the iframe once.** The field's only network call is
  `POST /v1/client/tokenize`. It writes nothing to `localStorage`,
  `sessionStorage`, IndexedDB or a cookie, and clears the inputs the moment a
  token comes back.
- **One script, hash-pinned.** The hosted-fields page loads exactly one script,
  from its own origin, with Subresource Integrity and a
  `Content-Security-Policy` of `default-src 'none'` plus a `connect-src` naming
  only the KnoxCall API.
- **Framing is bound, not open.** The page's `frame-ancestors` is the capability
  token's own origin list; a page that was not named cannot frame it at all.
- **Exact-origin, exact-window message trust,** in both directions, with strict
  shape validation and an explicit `targetOrigin`.
- **Context-bound ciphertexts** (`KnoxEncryptor`). The HKDF `info` pins tenant,
  app key, key version, datatype and the optional `purpose` data-role into the
  derived key; the `kc:` header rides as AES-GCM AAD. Decrypting under the wrong
  purpose, key, or a tampered header simply fails.

## Development

```sh
npm install
npm test          # vitest — includes a full ECIES decrypt round-trip against
                  # the server reference byte layout
npm run typecheck # tsc -p tsconfig.test.json (src + tests)
npm run build     # tsc -> dist/
```
