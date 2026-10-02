# @knoxcall/react

Hosted fields for React. `<SecureField>` embeds a KnoxCall-served iframe that
captures one sensitive value — an SSN, a bank account, an email, anything — and
exchanges it for a **vault token**. The value never enters your page's
JavaScript, your bundle, or your backend; your `onToken` callback receives the
token and display-safe metadata, never the value and never a ciphertext you
could mishandle.

KnoxCall holds no PCI DSS attestation and nothing here is a compliance control;
what it changes is *where the plaintext exists*. Card (`pan`) fields are refused
at capture today — see [Card fields](#card-fields-are-not-available-yet).

The security gate (exact-origin check + source-window check + strict message
shape validation) lives in the unit-tested protocol layer of
[`@knoxcall/browser`](https://www.npmjs.com/package/@knoxcall/browser), so this package and the vanilla
`mountSecureField` share one implementation of it.

## Install

```sh
npm install @knoxcall/react@^0.1.0 @knoxcall/browser@^0.1.0
```

Peer dependencies: `react >= 18`, `@knoxcall/browser >= 0.1.0`.

## How it works

1. **Your backend** mints a single-use capability token with its ordinary
   credentials, naming the vault and the exact page origins it may be used from.
2. **Your page** renders `<SecureField capabilityToken={…} format="ssn" />`.
3. **The customer** types into the iframe. Nothing crosses into your page but a
   `complete` boolean (and, for cards, a brand and last four).
4. **You** call `tokenize()` on submit. The iframe posts the value straight to
   KnoxCall and hands back the vault token.

The capability is single-use and expires in five minutes, so there is no
long-lived secret in the page and nothing worth stealing from it.

### Server side

```ts
// Your backend. POST /v1/client-tokens
app.post('/api/field-token', async (_req, res) => {
  res.json(await knox.crypto.mintClientToken({
    action: 'tokenize',
    vault: 'customer-ssn',                  // the ONE vault this may write into
    origins: ['https://shop.example.com'],  // exact origins, no wildcards
  }));
  // -> { token: "kct_…", expires_at, action, vault_id, origins }
});
```

### Client side

```tsx
import { SecureField, useSecureField } from '@knoxcall/react';

function SsnCapture({ capabilityToken }: { capabilityToken: string }) {
  const field = useSecureField();

  return (
    <form
      onSubmit={(e) => { e.preventDefault(); field.tokenize(); }}
    >
      <SecureField
        ref={field.ref}
        format="ssn"
        capabilityToken={capabilityToken}
        {...field.handlers}
        onToken={({ token }) => saveToServer(token)}
      />
      {field.error && <p role="alert">{field.error.message}</p>}
      <button type="submit" disabled={!field.complete}>Save</button>
    </form>
  );
}
```

`useSecureField()` gives you the state a form actually needs — `complete` for
the submit button, `error`, `token`, a `tokenize()` to call on submit, and a
`handlers` object to spread onto the component. Pass your own
`onChange`/`onError`/`onToken` into the hook to compose; they run after its own
state update, never instead of it.

You can skip the hook entirely and use a ref:

```tsx
const ref = useRef<SecureFieldRef>(null);
<SecureField ref={ref} format="email" capabilityToken={t} onToken={…} />;
// ref.current?.tokenize()
```

**Tokenizing is deliberately not triggered by a change event.** The component
this replaces sealed on the card-number field's `change`, once every field was
complete — so a customer typing number → expiry → CVC, the natural order, never
produced a token at all.

## `<SecureField>` props

| Prop | Type | Notes |
| --- | --- | --- |
| `format` | `'pan' \| 'ssn' \| 'bank_account' \| 'email' \| 'generic'` | Which inputs the iframe renders. A UI hint — the vault's real format is enforced server-side. |
| `capabilityToken` | `string` | The single-use `kct_…` token your backend minted. Anything else throws before an iframe exists. |
| `vault` | `string?` | Display/assertion only. The binding that matters is inside the capability token. |
| `elementBase` | `string?` | Where the hosted-fields page is served from. Defaults to `https://elements.knoxcall.com`. |
| `origins` | `string[]?` | Trusted origins for inbound messages. **Must be overridden together with `elementBase`** — otherwise every message from your own iframe is discarded and the field never reports ready. |
| `fieldStyle` | `KnoxFieldStyle?` | The constrained style object applied *inside* the iframe. |
| `style` / `className` | | Layout for the iframe element itself. |
| `title` | `string?` | Accessible name for the iframe. Defaults to `Secure field`. |
| `onReady` | `(msg) => void` | `{ format }` — the field rendered. |
| `onChange` | `(msg) => void` | `{ complete, brand?, last4? }`. |
| `onToken` | `(msg) => void` | `{ token, id, expires_at, last4?, brand?, exp_month?, exp_year? }`. |
| `onError` | `(msg) => void` | `{ code, message }`. |

`code` is one of `incomplete`, `invalid_token`, `origin_required`,
`card_program_unavailable`, `tokenize_failed`, `network_error`,
`session_expired` — a closed set, so you can branch on it exhaustively.

The iframe is created once per *identity*: changing `capabilityToken`, `format`,
`elementBase`, `origins` or `title` re-creates it (and clears whatever the
customer had typed); changing a callback does not.

## Formats

| `format` | Inputs | Validation in the iframe |
| --- | --- | --- |
| `ssn` | SSN / ITIN | 9 digits; refuses area `000`/`666`, group `00`, serial `0000`. `9xx` (ITIN) is accepted. |
| `bank_account` | routing + account | ABA 3-7-1 checksum; 4–17 account digits. The routing number rides along as `metadata.routing_number` — it identifies the bank, not the account. |
| `email` | email address | RFC-shape, ≤ 254 characters. |
| `generic` | one free-text input | non-empty. |
| `pan` | number, expiry, CVC | Luhn, length and CVC length by brand, real issuer ranges, expiry not in the past. **Refused at capture — see below.** |

Each input carries a label, `aria-invalid`, an `aria-describedby` error region
with `role="alert"`, a visible focus outline, and the `autocomplete` attribute
the platform expects (`cc-number`, `cc-exp`, `cc-csc`).

## Styling

A stylesheet cannot reach into a cross-origin iframe, so pass a constrained
style object instead — an allowlist of property names, each with a value
grammar:

```tsx
<SecureField
  format="generic"
  capabilityToken={t}
  fieldStyle={{
    color: '#111827',
    backgroundColor: '#ffffff',
    borderColor: '#d1d5db',
    borderRadius: '6px',
    borderWidth: '1px',
    fontSize: '15px',
    fontFamily: 'system',   // a NAME: system | sans | serif | mono
    lineHeight: '1.4',
    padding: '10px 12px',
    labelColor: '#374151',
    placeholderColor: '#9ca3af',
    errorColor: '#b42318',
  }}
/>
```

Anything outside that grammar is dropped silently — no class names, no arbitrary
CSS, no `url()`. CSS attribute selectors driving a background image are a
published way to read an input's value one character at a time, so free CSS is
the one thing a hosted field must never take from its parent.

## Card fields are not available yet

`format="pan"` renders and validates, but capturing into a card vault is refused
server-side: the request answers `403 card_program_unavailable`, which arrives
as `onError({ code: 'card_program_unavailable' })`. KnoxCall holds no
attestation covering card data, and the gate reads the attestation document
rather than a flag, so it opens by itself when one is filed and closes by itself
if one lapses. Use the non-card formats today.

## Security model

- **No API key in the browser.** The credential is a single-use `kct_`
  capability token bound to one vault and to the exact origins it may be
  presented from, valid for five minutes.
- **Three gates on every inbound message**, each bypassable alone: exact origin
  (string equality, so `https://elements.knoxcall.com.evil.com` never passes),
  our iframe's `contentWindow` (an origin check cannot see a *different window*
  at the same origin — which is what script injected into your own checkout is),
  and strict shape validation. A `knox:token` with no token is refused rather
  than delivered as `undefined`.
- **Explicit `targetOrigin` outbound, never `'*'`.**
- **A minimal iframe sandbox**: `allow-scripts allow-same-origin` and nothing
  else. No `allow-forms` (the page has no form and its CSP carries
  `form-action 'none'`), no `allow-popups`, no `allow-top-navigation` — a field
  that can navigate your checkout away is a phishing primitive.
  `allow-same-origin` is required: without it the document gets an opaque origin
  and its request to KnoxCall would carry `Origin: null`, which the server
  refuses. The frame is cross-origin to your page, so it restores only its own
  origin and grants it nothing of yours.
- **The value leaves the iframe once**, in one `POST /v1/client/tokenize`.
  Nothing is written to storage and the inputs are cleared as soon as a token
  comes back.

## Development

```sh
npm install
npm test          # vitest + jsdom — the origin/source/shape gate and callbacks
npm run typecheck # tsc -p tsconfig.test.json (src + tests)
npm run build     # tsc -> dist/
```
