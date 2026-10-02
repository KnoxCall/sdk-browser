// KnoxClient reveal/detokenize tests with a mocked fetch: endpoint + header
// construction, kct_ capability-token handling (an API key must never work
// here), and error paths.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { KnoxClient } from '../src/client.js';

interface SeenRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function makeFetch(status: number, body: unknown, opts: { jsonThrows?: boolean } = {}) {
  const seen: SeenRequest[] = [];
  const f = vi.fn(async (url: string, init?: any) => {
    seen.push({
      url,
      method: init?.method,
      headers: init?.headers ?? {},
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (opts.jsonThrows) throw new SyntaxError('Unexpected token < in JSON');
        return body;
      },
    };
  });
  return { f, seen };
}

const TOKEN = 'kct_0123456789abcdef';
const CT = 'kc:1:s:dGVuOmFwcDox:BAAA:aXY:Y3Q:$';

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── construction ─────────────────────────────────────────────────────────────

describe('KnoxClient construction', () => {
  it('throws when no fetch implementation is available', () => {
    vi.stubGlobal('fetch', undefined);
    expect(() => new KnoxClient()).toThrow(/no fetch available/);
  });

  it('throws when the supplied fetchImpl is not callable', () => {
    expect(() => new KnoxClient({ fetchImpl: 123 as any })).toThrow(/no fetch available/);
  });

  it('falls back to the global fetch when none is supplied', () => {
    const { f } = makeFetch(200, { data: 'x' });
    vi.stubGlobal('fetch', f);
    expect(() => new KnoxClient()).not.toThrow();
  });
});

// ── reveal ───────────────────────────────────────────────────────────────────

describe('KnoxClient.reveal', () => {
  it('POSTs the ciphertext to /v1/client/decrypt with a Bearer capability token', async () => {
    const { f, seen } = makeFetch(200, { data: { plaintext: 'plaintext-secret' }, meta: { request_id: 'r' } });
    const knox = new KnoxClient({ fetchImpl: f });

    const out = await knox.reveal(TOKEN, CT);

    expect(out).toBe('plaintext-secret');
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe('https://api.knoxcall.com/v1/client/decrypt');
    expect(seen[0].method).toBe('POST');
    expect(seen[0].headers['Content-Type']).toBe('application/json');
    expect(seen[0].headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(seen[0].body!)).toEqual({ data: CT });
  });

  it('returns the original typed value from the response envelope', async () => {
    const { f } = makeFetch(200, { data: { plaintext: { card: { last4: '4242' } } }, meta: { request_id: 'r' } });
    const knox = new KnoxClient({ fetchImpl: f });
    expect(await knox.reveal(TOKEN, CT)).toEqual({ card: { last4: '4242' } });
  });

  it('respects a custom baseUrl and strips a trailing slash', async () => {
    const { f, seen } = makeFetch(200, { data: 'x' });
    const knox = new KnoxClient({ baseUrl: 'https://sandbox.knoxcall.com/', fetchImpl: f });
    await knox.reveal(TOKEN, CT);
    expect(seen[0].url).toBe('https://sandbox.knoxcall.com/v1/client/decrypt');
  });

  it('rejects a missing token WITHOUT making a network call', async () => {
    const { f } = makeFetch(200, { data: 'x' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.reveal('', CT)).rejects.toThrow(/capability token/);
    expect(f).not.toHaveBeenCalled();
  });

  it('rejects non-kct_ credentials (an API key must never be used in the browser)', async () => {
    const { f } = makeFetch(200, { data: 'x' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.reveal('kc_live_apikey', CT)).rejects.toThrow(/kct_/);
    await expect(knox.reveal(`Bearer ${TOKEN}`, CT)).rejects.toThrow(/kct_/);
    await expect(knox.reveal('KCT_UPPERCASE', CT)).rejects.toThrow(/kct_/);
    expect(f).not.toHaveBeenCalled();
  });

  it('surfaces the server message on an error response', async () => {
    const { f } = makeFetch(403, { message: 'capability token already used' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.reveal(TOKEN, CT)).rejects.toThrow('capability token already used');
  });

  it('falls back to the error field, then a status message', async () => {
    const { f } = makeFetch(400, { error: 'payload does not match token binding' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.reveal(TOKEN, CT)).rejects.toThrow('payload does not match token binding');

    const nonJson = makeFetch(502, undefined, { jsonThrows: true });
    const knox2 = new KnoxClient({ fetchImpl: nonJson.f });
    await expect(knox2.reveal(TOKEN, CT)).rejects.toThrow('KnoxCall request failed (502)');
  });

  it('tolerates a 2xx response with a non-JSON body', async () => {
    const { f } = makeFetch(200, undefined, { jsonThrows: true });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.reveal(TOKEN, CT)).resolves.toBeUndefined();
  });
});

// ── detokenize ───────────────────────────────────────────────────────────────

describe('KnoxClient.detokenize', () => {
  it('POSTs the vault token to /v1/client/detokenize and returns .value', async () => {
    const { f, seen } = makeFetch(200, { data: { value: '4242424242424242' }, meta: { request_id: 'r' } });
    const knox = new KnoxClient({ fetchImpl: f });

    const out = await knox.detokenize(TOKEN, 'tok_visa_abc123');

    expect(out).toBe('4242424242424242');
    expect(seen[0].url).toBe('https://api.knoxcall.com/v1/client/detokenize');
    expect(seen[0].method).toBe('POST');
    expect(seen[0].headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(seen[0].body!)).toEqual({ data: 'tok_visa_abc123' });
  });

  it('applies the same kct_ guard as reveal', async () => {
    const { f } = makeFetch(200, { value: 'x' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.detokenize('sk_live_nope', 'tok_x')).rejects.toThrow(/kct_/);
    expect(f).not.toHaveBeenCalled();
  });

  it('surfaces server errors', async () => {
    const { f } = makeFetch(404, { message: 'vault token not found' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.detokenize(TOKEN, 'tok_missing')).rejects.toThrow('vault token not found');
  });
});

// ── tokenize (Card-Grade Vaults A1) ─────────────────────────────────────────

describe('KnoxClient.tokenize', () => {
  it('POSTs the value to /v1/client/tokenize and returns the whole data object', async () => {
    const { f, seen } = makeFetch(200, {
      data: { token: '411111999991111', id: 'vt-1', last4: '1111', brand: 'visa', expires_at: null },
      meta: { request_id: 'r' },
    });
    const knox = new KnoxClient({ fetchImpl: f });

    const out = await knox.tokenize(TOKEN, '4111111111111111');

    // The whole object, not just the token: `last4`/`brand` are what a checkout
    // renders once the number is gone.
    expect(out).toEqual({
      token: '411111999991111', id: 'vt-1', last4: '1111', brand: 'visa', expires_at: null,
    });
    expect(seen[0].url).toBe('https://api.knoxcall.com/v1/client/tokenize');
    expect(seen[0].method).toBe('POST');
    expect(seen[0].headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(seen[0].body!)).toEqual({ value: '4111111111111111' });
  });

  it('sends metadata and ttl_seconds only when supplied', async () => {
    const { f, seen } = makeFetch(200, { data: { token: 't', id: 'i', expires_at: null } });
    const knox = new KnoxClient({ fetchImpl: f });

    await knox.tokenize(TOKEN, 'v', { metadata: { order: '42' }, ttlSeconds: 900 });
    expect(JSON.parse(seen[0].body!)).toEqual({ value: 'v', metadata: { order: '42' }, ttl_seconds: 900 });

    await knox.tokenize(TOKEN, 'v', {});
    // An absent option must not become an explicit null — the server treats
    // `ttl_seconds: null` as "no expiry", which is not what "unspecified" means.
    expect(JSON.parse(seen[1].body!)).toEqual({ value: 'v' });
  });

  it('applies the same kct_ guard as reveal — an API key must never reach the network', async () => {
    const { f } = makeFetch(200, { data: {} });
    const knox = new KnoxClient({ fetchImpl: f });
    for (const bad of ['', 'tk_live_nope', 'kc_live_apikey', `Bearer ${TOKEN}`, 'KCT_UPPERCASE']) {
      await expect(knox.tokenize(bad, 'v')).rejects.toThrow(/kct_/);
    }
    expect(f).not.toHaveBeenCalled();
  });

  it('never puts the value in the URL or a header — only the body', async () => {
    const { f, seen } = makeFetch(200, { data: { token: 't', id: 'i', expires_at: null } });
    const knox = new KnoxClient({ fetchImpl: f });
    await knox.tokenize(TOKEN, '4111111111111111');
    expect(seen[0].url).not.toContain('4111');
    expect(JSON.stringify(seen[0].headers)).not.toContain('4111');
  });

  it('surfaces the server refusal message', async () => {
    const { f } = makeFetch(401, { message: 'Capability token is invalid, expired, already used, or not bound to this origin.' });
    const knox = new KnoxClient({ fetchImpl: f });
    await expect(knox.tokenize(TOKEN, 'v')).rejects.toThrow(/not bound to this origin/);
  });
});
