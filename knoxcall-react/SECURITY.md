# Security Policy

KnoxCall is a credential-custody platform; the security of this SDK is part of
that promise. We appreciate reports from the community.

## Supported versions

| Package | Version | Supported |
|---|---|---|
| `@knoxcall/react` on npm | 0.1.x | yes — security fixes are released as a new patch version |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
GitHub issue for a security report.

- Email: **security@knoxcall.com**

Include the affected version, the SDK surface involved (client-side sealing,
a hosted field and its postMessage checks, the reveal helper, …) and a proof of
concept where possible.
Please do not include real customer secrets or tokens in your report.

| Timeline | Action |
|---|---|
| Within 24 hours | Acknowledgement of your report |
| Within 72 hours | Initial assessment and severity classification |
| Within 14 days | Remediation plan confirmed and shared with you |
| Within 90 days | Fix released (critical / high); coordinated disclosure |

We support coordinated disclosure and credit reporters who wish to be named
once a fix is released.

## Scope

In scope: `<SecureField>` and `useSecureField`, and any prop or callback path
that could expose a hosted field's value or capability token to your page.
Both wrap `@knoxcall/browser`'s `mountSecureField`, so the origin, window and
message-shape checks are that package's; report them against either one.

Out of scope: vulnerabilities in your own application code, including how your
backend mints capability tokens; the browser itself; issues that require a
pre-compromised device or a malicious browser extension; and `<Reveal>`, which
is exported but not yet usable because the page it loads is not served. Report
issues in the KnoxCall API itself to the same address.

## How this SDK handles secrets

- No API key is ever shipped to the browser. Your backend mints the capability
  token a field needs and hands the page only that.
- A hosted field's value lives in a cross-origin iframe and leaves it once, in
  the tokenize request. Your components receive a vault token and display-safe
  metadata (`last4`, `brand` and the expiry month and year, where the vault's
  format allows them), never the value or a ciphertext.
- Messages from a hosted field are accepted only from an exact KnoxCall element
  origin (never a prefix match) and only from your own iframe's window.

## Automated checks

The SDK's source of truth is the KnoxCall monorepo, whose CI runs this SDK's test suite
and a dependency audit (`npm audit`) on every change, plus CodeQL and Trivy.
