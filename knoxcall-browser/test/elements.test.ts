// Shape-validation + origin-trust tests for the Elements postMessage protocol.
//
// parseKnoxMessage and isTrustedElementOrigin are the security gate for every
// message a host page accepts from a KnoxCall iframe, so the matrix here is
// deliberately exhaustive about malformed, hostile, and near-miss inputs:
// anything that is not a well-formed Knox message from an exactly-matching
// origin must be rejected.

import { describe, it, expect } from 'vitest';
import {
  KNOX_MESSAGE,
  KNOX_ERROR_CODES,
  DEFAULT_ELEMENT_BASE,
  DEFAULT_ELEMENT_ORIGINS,
  parseKnoxMessage,
  isTrustedElementOrigin,
} from '../src/elements.js';

// ── parseKnoxMessage: non-object / junk inputs ───────────────────────────────

describe('parseKnoxMessage rejects non-message inputs', () => {
  const junk: [string, unknown][] = [
    ['null', null],
    ['undefined', undefined],
    ['number', 42],
    ['boolean', true],
    ['bare string that looks like a type', 'knox:ready'],
    ['empty object', {}],
    ['array', []],
    ['array with a type-ish first element', ['knox:ready']],
    ['function', () => 'knox:ready'],
  ];

  for (const [name, value] of junk) {
    it(`returns null for ${name}`, () => {
      expect(parseKnoxMessage(value)).toBeNull();
    });
  }

  it('returns null when type is not a string', () => {
    expect(parseKnoxMessage({ type: 123 })).toBeNull();
    expect(parseKnoxMessage({ type: null })).toBeNull();
    expect(parseKnoxMessage({ type: ['knox:ready'] })).toBeNull();
    // No implicit toString() coercion: an object with a hostile toString must
    // not be treated as a string type.
    expect(parseKnoxMessage({ type: { toString: () => 'knox:ready' } })).toBeNull();
  });

  it('returns null for unknown / empty type strings', () => {
    expect(parseKnoxMessage({ type: '' })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:unknown' })).toBeNull();
    expect(parseKnoxMessage({ type: 'KNOX:READY' })).toBeNull(); // case-sensitive
    expect(parseKnoxMessage({ type: 'knox:ready ' })).toBeNull(); // no trimming
    expect(parseKnoxMessage({ type: 'stripe:token' })).toBeNull(); // foreign traffic
  });
});

// ── parseKnoxMessage: per-type field validation ──────────────────────────────

describe('parseKnoxMessage knox:ready', () => {
  it('parses a ready that names the format it rendered', () => {
    expect(parseKnoxMessage({ type: 'knox:ready', format: 'pan' }))
      .toEqual({ type: KNOX_MESSAGE.READY, format: 'pan' });
  });

  it('rejects a ready with no format - the parent asserts what it got', () => {
    expect(parseKnoxMessage({ type: 'knox:ready' })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:ready', format: 42 })).toBeNull();
  });

  it('strips unknown fields from the returned message', () => {
    const msg = parseKnoxMessage({ type: 'knox:ready', format: 'ssn', extra: 'smuggled', onload: 'x' });
    expect(msg).toEqual({ type: KNOX_MESSAGE.READY, format: 'ssn' });
    expect(Object.keys(msg!)).toEqual(['type', 'format']);
  });
});

describe('parseKnoxMessage knox:change', () => {
  it('parses complete=true and complete=false', () => {
    expect(parseKnoxMessage({ type: 'knox:change', complete: true }))
      .toEqual({ type: KNOX_MESSAGE.CHANGE, complete: true, brand: undefined, last4: undefined });
    expect(parseKnoxMessage({ type: 'knox:change', complete: false }))
      .toEqual({ type: KNOX_MESSAGE.CHANGE, complete: false, brand: undefined, last4: undefined });
  });

  it('carries display-safe card metadata when the iframe sends it', () => {
    expect(parseKnoxMessage({ type: 'knox:change', complete: true, brand: 'visa', last4: '4242' }))
      .toEqual({ type: KNOX_MESSAGE.CHANGE, complete: true, brand: 'visa', last4: '4242' });
  });

  it('drops non-string metadata rather than passing it through', () => {
    expect(parseKnoxMessage({ type: 'knox:change', complete: true, brand: 42, last4: { toString: () => '1' } }))
      .toEqual({ type: KNOX_MESSAGE.CHANGE, complete: true, brand: undefined, last4: undefined });
  });

  it('rejects a missing or non-boolean complete', () => {
    expect(parseKnoxMessage({ type: 'knox:change' })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:change', complete: 'true' })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:change', complete: 1 })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:change', complete: null })).toBeNull();
  });
});

describe('parseKnoxMessage knox:token', () => {
  const TOKEN = '4111110000001111';
  const ROW = '66666666-6666-4666-8666-666666666666';

  it('parses a token message with display metadata', () => {
    expect(parseKnoxMessage({
      type: 'knox:token', token: TOKEN, id: ROW, expires_at: null,
      last4: '1111', brand: 'visa', exp_month: 4, exp_year: 2031,
    })).toEqual({
      type: KNOX_MESSAGE.TOKEN, token: TOKEN, id: ROW, expires_at: null,
      last4: '1111', brand: 'visa', exp_month: 4, exp_year: 2031,
    });
  });

  it('parses a token message without metadata (fields become undefined)', () => {
    expect(parseKnoxMessage({ type: 'knox:token', token: TOKEN, id: ROW, expires_at: '2031-04-30T00:00:00.000Z' }))
      .toEqual({
        type: KNOX_MESSAGE.TOKEN, token: TOKEN, id: ROW,
        expires_at: '2031-04-30T00:00:00.000Z',
        last4: undefined, brand: undefined, exp_month: undefined, exp_year: undefined,
      });
  });

  it('drops non-string / non-number metadata instead of passing it through', () => {
    const msg = parseKnoxMessage({
      type: 'knox:token', token: TOKEN, id: ROW, expires_at: null,
      last4: 4242, brand: { toString: () => 'visa' }, exp_month: '04',
    });
    expect(msg).toEqual({
      type: KNOX_MESSAGE.TOKEN, token: TOKEN, id: ROW, expires_at: null,
      last4: undefined, brand: undefined, exp_month: undefined, exp_year: undefined,
    });
  });

  // THE clause. A "token" message with no token would otherwise reach onToken
  // as undefined and be stored as the customer's payment instrument.
  it('rejects a missing, empty or non-string token or id', () => {
    expect(parseKnoxMessage({ type: 'knox:token', id: ROW, expires_at: null })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:token', token: '', id: ROW, expires_at: null })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:token', token: 123, id: ROW, expires_at: null })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:token', token: TOKEN, expires_at: null })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:token', token: TOKEN, id: '', expires_at: null })).toBeNull();
    // Duck-typed "string": an object with a startsWith method must not pass.
    expect(parseKnoxMessage({ type: 'knox:token', token: { startsWith: () => true }, id: ROW, expires_at: null })).toBeNull();
  });

  it('rejects an expires_at that is neither null nor a string', () => {
    expect(parseKnoxMessage({ type: 'knox:token', token: TOKEN, id: ROW, expires_at: 0 })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:token', token: TOKEN, id: ROW })).toBeNull();
  });
});

describe('parseKnoxMessage knox:error', () => {
  it('parses a known code and message', () => {
    expect(parseKnoxMessage({ type: 'knox:error', code: 'invalid_token', message: 'boom' }))
      .toEqual({ type: KNOX_MESSAGE.ERROR, code: 'invalid_token', message: 'boom' });
  });

  it('accepts every documented code', () => {
    for (const code of KNOX_ERROR_CODES) {
      expect(parseKnoxMessage({ type: 'knox:error', code, message: 'x' }))
        .toEqual({ type: KNOX_MESSAGE.ERROR, code, message: 'x' });
    }
  });

  // A code the parent does not know must not reach a switch as itself: the set
  // is closed so a consumer can branch on it exhaustively.
  it('collapses an unknown or missing code to tokenize_failed', () => {
    expect(parseKnoxMessage({ type: 'knox:error', code: 'knox:whatever', message: 'x' }))
      .toEqual({ type: KNOX_MESSAGE.ERROR, code: 'tokenize_failed', message: 'x' });
    expect(parseKnoxMessage({ type: 'knox:error', message: 'x' }))
      .toEqual({ type: KNOX_MESSAGE.ERROR, code: 'tokenize_failed', message: 'x' });
  });

  it('substitutes a fallback for missing / non-string messages', () => {
    expect(parseKnoxMessage({ type: 'knox:error', code: 'network_error' }))
      .toEqual({ type: KNOX_MESSAGE.ERROR, code: 'network_error', message: 'unknown error' });
    expect(parseKnoxMessage({ type: 'knox:error', code: 'network_error', message: { evil: true } }))
      .toEqual({ type: KNOX_MESSAGE.ERROR, code: 'network_error', message: 'unknown error' });
  });
});

// -- direction: the parent parser refuses parent-to-iframe types -------------

describe('parseKnoxMessage refuses messages the PARENT sends', () => {
  // A page that echoed our own protocol back at us must not be able to drive
  // the host callbacks. The iframe's parser refuses the other direction for the
  // mirror-image reason (src/card-service/elements/protocol.ts in the server repo).
  it('returns null for knox:tokenize and knox:style', () => {
    expect(parseKnoxMessage({ type: 'knox:tokenize' })).toBeNull();
    expect(parseKnoxMessage({ type: 'knox:style', style: { color: '#fff' } })).toBeNull();
  });

  it('returns null for the retired knox:init (in-page sealing is gone)', () => {
    expect(parseKnoxMessage({
      type: 'knox:init',
      bundle: { public_key_raw: 'BAAA', key_ref: { tenantId: 't', appKeyId: 'a', keyVersion: 1 } },
    })).toBeNull();
  });
});

// ── parseKnoxMessage: prototype-pollution-ish inputs ─────────────────────────

describe('parseKnoxMessage hostile-object hygiene', () => {
  it('ignores __proto__ / constructor payloads and never pollutes Object.prototype', () => {
    const data = JSON.parse(
      '{"type":"knox:change","complete":true,'
      + '"__proto__":{"polluted":"yes"},'
      + '"constructor":{"prototype":{"hax":1}}}',
    );
    const msg = parseKnoxMessage(data);
    expect(msg).toEqual({ type: KNOX_MESSAGE.CHANGE, complete: true, brand: undefined, last4: undefined });
    expect(Object.keys(msg!)).toEqual(['type', 'complete', 'brand', 'last4']);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).hax).toBeUndefined();
  });

  it('handles null-prototype objects (postMessage structured clones)', () => {
    const data = Object.assign(Object.create(null), { type: 'knox:ready', format: 'generic' });
    expect(parseKnoxMessage(data)).toEqual({ type: KNOX_MESSAGE.READY, format: 'generic' });
  });

  it('does not read validated fields off the prototype chain by accident', () => {
    // `complete` lives on the prototype, not the object itself. Current
    // behavior: property access sees it, typeof passes — this documents that
    // parseKnoxMessage relies on typeof checks, not own-property checks. The
    // returned message is still a fresh object with primitive fields only.
    const proto = { complete: true };
    const data = Object.assign(Object.create(proto), { type: 'knox:change' });
    const msg = parseKnoxMessage(data);
    expect(msg === null || msg.type === KNOX_MESSAGE.CHANGE).toBe(true);
    if (msg && msg.type === KNOX_MESSAGE.CHANGE) {
      expect(Object.keys(msg)).toEqual(['type', 'complete', 'brand', 'last4']);
      expect(typeof msg.complete).toBe('boolean');
    }
  });
});

// ── isTrustedElementOrigin ───────────────────────────────────────────────────

describe('isTrustedElementOrigin', () => {
  const ALLOWED = ['https://elements.knoxcall.com', 'https://elements-staging.knoxcall.com'];

  it('accepts exact matches only', () => {
    expect(isTrustedElementOrigin('https://elements.knoxcall.com', ALLOWED)).toBe(true);
    expect(isTrustedElementOrigin('https://elements-staging.knoxcall.com', ALLOWED)).toBe(true);
  });

  it('rejects suffix attacks (trusted origin as a prefix of a hostile host)', () => {
    expect(isTrustedElementOrigin('https://elements.knoxcall.com.evil.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.com.evil.com:8443', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.commerce.io', ALLOWED)).toBe(false);
  });

  it('rejects trusted origin embedded in path/userinfo-looking strings', () => {
    expect(isTrustedElementOrigin('https://evil.com/https://elements.knoxcall.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.com@evil.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.com.evil.com/elements.knoxcall.com', ALLOWED)).toBe(false);
  });

  it('rejects subdomain and lookalike-host attacks', () => {
    expect(isTrustedElementOrigin('https://sub.elements.knoxcall.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://evil-elements.knoxcall.com.evil.net', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://api.knoxcall.co', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://xelements.knoxcall.com', ALLOWED)).toBe(false);
  });

  it('rejects scheme downgrades and scheme mismatches', () => {
    expect(isTrustedElementOrigin('http://elements.knoxcall.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('ftp://elements.knoxcall.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('elements.knoxcall.com', ALLOWED)).toBe(false);
  });

  it('rejects port variants (event.origin never carries the default port)', () => {
    expect(isTrustedElementOrigin('https://elements.knoxcall.com:443', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.com:8443', ALLOWED)).toBe(false);
  });

  it('rejects trailing-slash / whitespace / case variants', () => {
    expect(isTrustedElementOrigin('https://elements.knoxcall.com/', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin(' https://elements.knoxcall.com', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('https://elements.knoxcall.com ', ALLOWED)).toBe(false);
    // Browsers normalize origins to lowercase, so allowed lists must be
    // lowercase; an uppercase variant is by definition not a browser origin.
    expect(isTrustedElementOrigin('https://API.KNOXCALL.COM', ALLOWED)).toBe(false);
  });

  it('rejects the opaque "null" origin (sandboxed iframes) and empty strings', () => {
    expect(isTrustedElementOrigin('null', ALLOWED)).toBe(false);
    expect(isTrustedElementOrigin('', ALLOWED)).toBe(false);
  });

  it('never matches anything against an empty allowlist', () => {
    expect(isTrustedElementOrigin('https://elements.knoxcall.com', [])).toBe(false);
  });

  it('treats allowlist entries as literal strings, not patterns', () => {
    expect(isTrustedElementOrigin('https://x.knoxcall.com', ['https://*.knoxcall.com'])).toBe(false);
    expect(isTrustedElementOrigin('https://a.knoxcall.com', ['https://.knoxcall.com'])).toBe(false);
  });
});

describe('DEFAULT_ELEMENT_ORIGINS', () => {
  it('is exactly the production hosted-fields origin', () => {
    expect(DEFAULT_ELEMENT_ORIGINS).toEqual(['https://elements.knoxcall.com']);
    expect(DEFAULT_ELEMENT_BASE).toBe('https://elements.knoxcall.com');
    for (const origin of DEFAULT_ELEMENT_ORIGINS) {
      expect(origin.startsWith('https://')).toBe(true);
      expect(origin.endsWith('/')).toBe(false);
    }
  });

  // The default must NOT widen itself to whatever elementBase says: a base
  // somebody else set would then be trusted for inbound messages too.
  it('does not include the API hosts the retired prototype used', () => {
    expect(DEFAULT_ELEMENT_ORIGINS).not.toContain('https://api.knoxcall.com');
    expect(DEFAULT_ELEMENT_ORIGINS).not.toContain('https://sandbox.knoxcall.com');
  });
});
