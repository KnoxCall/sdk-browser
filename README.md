# KnoxCall browser SDKs

Official KnoxCall SDKs for the browser. Two packages live here side by side,
because `@knoxcall/react` builds on `@knoxcall/browser`.

| Package | Install | What it does |
| --- | --- | --- |
| [`@knoxcall/browser`](knoxcall-browser) | `npm install @knoxcall/browser` | Seals a value into a `kc:` ciphertext in the page with your tenant's public key, and mounts KnoxCall hosted fields without a framework. |
| [`@knoxcall/react`](knoxcall-react) | `npm install @knoxcall/react` | `<SecureField>` and `useSecureField`: a KnoxCall hosted field in a cross-origin iframe, so the typed value never enters your page's JavaScript. |

Guides: [docs.knoxcall.com/sdks/elements](https://docs.knoxcall.com/sdks/elements).
Each package's README covers its API in full.

## This repository is a mirror

It is a read-only copy of the KnoxCall monorepo, overwritten whenever these
packages change on its main branch. Issues are welcome here; pull requests are
not merged.

## Security

Report a vulnerability to **security@knoxcall.com**, not in a public issue. See
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
