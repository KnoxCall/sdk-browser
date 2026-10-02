// @knoxcall/browser — client-side READ (reveal) helpers.
//
// The counterpart to KnoxEncryptor: a browser exchanges a single-use, payload-
// pinned capability token (minted server-side by your backend) for
// the plaintext of ONE bound value — decrypt a kc: ciphertext or detokenize a
// vault token — without ever holding an API key.
//
//   const bundle = await fetch('/my-backend/reveal-token', ...).then(r => r.json());
//   const knox = new KnoxClient();
//   const pan = await knox.reveal(bundle.token, ciphertext);

// Loosely typed so this file needs neither DOM nor Node fetch typings.
type FetchLike = (input: string, init?: any) => Promise<any>;

export interface KnoxClientOptions {
  baseUrl?: string;
  fetchImpl?: FetchLike;
}

const DEFAULT_BASE = 'https://api.knoxcall.com';

/** What `POST /v1/client/tokenize` returns inside the `{data, meta}` envelope. */
export interface TokenizeResult {
  /** The vault token. Store this; it is what the proxy resolves later. */
  token: string;
  /** The vault-token row id, for metadata updates and audit correlation. */
  id: string;
  /** Card vaults only — the last four digits, safe to display. */
  last4?: string;
  /** Card vaults only — the brand derived from the BIN, when it is recognised. */
  brand?: string;
  /** ISO timestamp, or null when the vault sets no TTL. */
  expires_at: string | null;
}

export class KnoxClient {
  private readonly base: string;
  private readonly f: FetchLike;

  constructor(opts: KnoxClientOptions = {}) {
    this.base = (opts.baseUrl ?? DEFAULT_BASE).replace(/\/$/, '');
    const f = opts.fetchImpl ?? (globalThis as any).fetch;
    if (typeof f !== 'function') {
      throw new Error('KnoxClient: no fetch available — pass { fetchImpl }');
    }
    this.f = f;
  }

  // Reveal the plaintext of the bound kc: ciphertext. Single-use: the token is
  // consumed server-side. Returns the original typed value.
  // The server wraps responses in the `{data, meta}` envelope, so the revealed
  // value is at `data.plaintext` (not the response root).
  async reveal(capabilityToken: string, ciphertext: string): Promise<unknown> {
    const json = await this.post('/v1/client/decrypt', capabilityToken, { data: ciphertext });
    return json?.data?.plaintext;
  }

  // Reveal the value behind the bound vault token. Single-use. The value is at
  // `data.value` inside the `{data, meta}` envelope.
  async detokenize(capabilityToken: string, vaultToken: string): Promise<string> {
    const json = await this.post('/v1/client/detokenize', capabilityToken, { data: vaultToken });
    return json?.data?.value;
  }

  // Put a sensitive value INTO the vault the capability token was minted
  // against, and get the vault token back — the inverse of `detokenize`, and
  // the direction that keeps the value out of your backend entirely.
  //
  // Single-use, and bound to the page's ORIGIN as well as the vault: the token
  // your backend minted named the exact origins it may be presented from, and
  // the browser sends that origin automatically. There is nothing to pass here
  // for it, and nothing you can pass that would change it.
  //
  // Returns the whole `data` object, not just the token, because the
  // display-safe metadata beside it (`last4`, `brand` on a card vault) is what
  // a checkout renders once the number is gone. `expires_at` is null when the
  // vault sets no TTL.
  async tokenize(
    capabilityToken: string,
    value: string,
    opts?: { metadata?: Record<string, unknown>; ttlSeconds?: number },
  ): Promise<TokenizeResult> {
    const body: Record<string, unknown> = { value };
    if (opts?.metadata !== undefined) body.metadata = opts.metadata;
    if (opts?.ttlSeconds !== undefined) body.ttl_seconds = opts.ttlSeconds;
    const json = await this.post('/v1/client/tokenize', capabilityToken, body);
    return json?.data;
  }

  private async post(path: string, token: string, body: unknown): Promise<any> {
    if (!token || !token.startsWith('kct_')) {
      throw new Error('a client capability token (kct_…) is required');
    }
    const res = await this.f(`${this.base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    let json: any = undefined;
    try { json = await res.json(); } catch { /* non-JSON body */ }
    if (!res.ok) {
      throw new Error(json?.message || json?.error || `KnoxCall request failed (${res.status})`);
    }
    return json ?? {};
  }
}
