# Changelog

This project adheres to [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

**First release: 0.1.0, 2026-09-27** — published to npm as `@knoxcall/react` (monorepo tag `knoxcall-react-v0.1.0`).

## [Unreleased]

### Changed
- **0.1.1 — docs: registry install instructions; no code change.** A registry renders the README that was inside the version it published and never lets it be edited, so the README inside the previous release still showed pre-release install instructions (build from a source checkout) after the package was live; the corrected README reaches a registry only as a new version. The README's link to `@knoxcall/browser` pointed at a sibling folder that no registry carries and now points at its npm page. `package.json` gains `homepage` (docs.knoxcall.com/sdks/elements), `repository` (the public mirror KnoxCall/sdk-browser, which holds this package in `knoxcall-react/` beside its sibling) and `bugs` (that mirror's issue tracker), and its `description` no longer lists card capture (refused server-side today — see "Card fields are not available yet") or a Reveal component (its hosted page is not served yet).

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
- `<SecureField>` and `useSecureField()` — hosted fields for React. One component
  for every format (`ssn`, `bank_account`, `email`, `generic`; `pan` renders but
  is refused server-side until the card programme's Gate 3), tokenizing on an
  explicit `tokenize()` rather than on a `change` event, with the iframe's
  configuration injected by KnoxCall rather than posted by the host page.
  Themable through a constrained style object — never arbitrary CSS.

### Changed
- **`<CardCollect>` is replaced by `<SecureField>`.** It sealed a `kc:`
  ciphertext in an iframe at `{elementBase}/ui/elements/card`, which nothing ever
  served; `<SecureField>` captures into a vault at
  `https://elements.knoxcall.com/field` and hands back a vault token. Three
  defects of the old component are closed by construction: it sealed on a
  `change` event that never fired in the natural typing order, it discarded the
  expiry, and it took its key from whichever window messaged it first.

### Deprecated
- `<Reveal>` is still exported but **UNFINISHED**: the reveal page is not served,
  so its iframe does not load. Marked in the source with what is missing, and
  excluded from the README.
