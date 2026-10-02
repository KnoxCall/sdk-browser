# Changelog

This project adheres to [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

**First release: 0.1.0, 2026-09-27** — published to npm as `@knoxcall/browser` (monorepo tag `knoxcall-browser-v0.1.0`).

## [Unreleased]

### Changed
- **0.1.1 — docs: registry install instructions; no code change.** A registry renders the README that was inside the version it published and never lets it be edited, so the README inside the previous release still showed pre-release install instructions (build from a source checkout) after the package was live; the corrected README reaches a registry only as a new version. The README's links to `@knoxcall/react` pointed at a sibling folder that no registry carries and now point at its npm page. `package.json` gains `homepage` (docs.knoxcall.com/sdks/elements), `repository` (the public mirror KnoxCall/sdk-browser, which holds this package in `knoxcall-browser/` beside its sibling) and `bugs` (that mirror's issue tracker), and its `description` now names what the package ships — hosted fields, single-use-token reveal and client-side `kc:` encryption — instead of encryption alone.

## [0.1.0] — 2026-09-27

> **This section was headed `## [0.1.0] — 2026-08-04` and described it as a
> Initial release until 2026-08-23. That release never happened**: `git tag --list` is
> empty, the package name was still unclaimed at the last check (2026-08-11,
> `docs/internal/runbooks/sdk-publish.md`), and no artifact was ever pushed to a
> registry. The same fabricated-release shape was removed from the Terraform
> provider's changelog on 2026-08-06; this is that correction applied to the
> remaining packages. The content below is accurate — it is the work that will
> ship in the first release — only the heading was a claim.
>
> `tests/coverage/sdk-changelog-honesty.test.ts` now refuses any release heading
> with no matching git tag, so this cannot recur silently.

### Added
- `KnoxEncryptor` — client-side `kc:` sealing of PANs/PII in the page using
  ECDH P-256 + HKDF-SHA256 + AES-256-GCM, with only the tenant public key in
  the browser (the decrypting key stays server-side).
- One-shot capability-token redemption helpers and the `BrowserDpopKeyPair`
  helper for sender-constrained tokens.
- `mountSecureField(container, opts)` — hosted fields. Mounts a KnoxCall-served
  iframe from `https://elements.knoxcall.com` that captures one sensitive value
  and exchanges it for a vault token, so the value never enters the host page's
  JavaScript. Returns `{ tokenize(), setStyle(), destroy(), on(), iframe }`.
  Formats: `ssn`, `bank_account`, `email`, `generic`; `pan` renders but is
  refused server-side with `card_program_unavailable` (Card-Grade Vaults Gate 3).
- `KnoxClient.tokenize()` — the consume half of the `tokenize` capability action.

### Changed
- **The Elements postMessage protocol is the hosted-fields protocol now.**
  `knox:token` carries `{token, id, expires_at, last4?, brand?, exp_month?,
  exp_year?}` — a VAULT TOKEN — where it used to carry a `kc:` ciphertext;
  `knox:ready` names the format; `knox:change` carries display-safe card
  metadata; `knox:error` carries a code from a closed set; and `knox:tokenize` /
  `knox:style` are the two messages a parent may send. `parseKnoxMessage` refuses
  the parent→iframe types outright, so a page echoing the protocol back reaches
  nothing.
- `DEFAULT_ELEMENT_ORIGINS` is `['https://elements.knoxcall.com']` (was the API
  and sandbox hosts, which never served an element). `DEFAULT_ELEMENT_BASE` is
  exported beside it.

### Removed
- `knox:init` and the in-page sealing handshake it carried. Handing the iframe a
  sealing bundle chosen by the host page is what let script on that page
  substitute its own key — and in-page sealing puts the plaintext in the host
  page's JavaScript, which the hosted fields exist to avoid. `KnoxEncryptor` is
  unchanged and still available for the cases where that trade is the right one.
