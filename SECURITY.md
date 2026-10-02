# Security Policy

This repository mirrors two KnoxCall packages, side by side. KnoxCall is a
credential-custody platform; the security of these SDKs is part of that
promise. We appreciate reports from the community.

## Supported versions

| Package | Version | Supported |
|---|---|---|
| `@knoxcall/browser` on npm | 0.1.x | yes — security fixes are released as a new patch version |
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

Each package's policy lists what is in scope and how it handles secrets:

- [`knoxcall-browser/SECURITY.md`](knoxcall-browser/SECURITY.md)
- [`knoxcall-react/SECURITY.md`](knoxcall-react/SECURITY.md)
