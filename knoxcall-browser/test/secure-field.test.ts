// `mountSecureField` — the pure half.
//
// This config runs in `node`, so the DOM-level behaviour of `mountSecureField`
// (the origin + source + shape gate, callback wiring, teardown) is exercised in
// `@knoxcall/react`'s jsdom suite, which drives the same implementation through
// `<SecureField>`. What is asserted HERE is everything that can be checked
// without a document — and everything checked here is security-relevant:
//
//   * the iframe URL is built from the elementBase we were given, with the
//     capability token URL-encoded, and nothing else smuggled into it;
//   * the sandbox attribute grants exactly two capabilities, and specifically
//     NOT `allow-forms`, `allow-popups` or `allow-top-navigation`;
//   * a token that is not a `kct_` capability is refused at the call, before an
//     iframe exists — so a page that accidentally passes an API key does not
//     put it in a URL.

import { describe, it, expect } from 'vitest';
import {
  SECURE_FIELD_SANDBOX,
  secureFieldSrc,
  mountSecureField,
} from '../src/secure-field.js';
import { DEFAULT_ELEMENT_BASE } from '../src/elements.js';

const TOKEN = 'kct_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';

describe('secureFieldSrc', () => {
  it('defaults to the production hosted-fields origin', () => {
    expect(secureFieldSrc({ format: 'pan', capabilityToken: TOKEN }))
      .toBe(`${DEFAULT_ELEMENT_BASE}/field?t=${TOKEN}&format=pan`);
  });

  it('honours an explicit elementBase and strips a trailing slash', () => {
    expect(secureFieldSrc({ elementBase: 'https://elements-staging.knoxcall.com/', format: 'ssn', capabilityToken: TOKEN }))
      .toBe(`https://elements-staging.knoxcall.com/field?t=${TOKEN}&format=ssn`);
  });

  it('URL-encodes the capability token rather than concatenating it', () => {
    // A token is base64url and needs no escaping today. Asserted anyway: the
    // day one carries a character that does not, string concatenation would let
    // it add a query parameter of its own.
    const src = secureFieldSrc({ format: 'generic', capabilityToken: 'kct_a&format=pan&x=y' });
    const url = new URL(src);
    expect(url.searchParams.get('t')).toBe('kct_a&format=pan&x=y');
    expect(url.searchParams.get('format')).toBe('generic');
    expect(url.searchParams.getAll('format')).toEqual(['generic']);
  });

  it('never puts the token in the path or the fragment', () => {
    const url = new URL(secureFieldSrc({ format: 'pan', capabilityToken: TOKEN }));
    expect(url.pathname).toBe('/field');
    expect(url.hash).toBe('');
  });
});

describe('the iframe sandbox', () => {
  it('grants exactly allow-scripts and allow-same-origin', () => {
    expect(SECURE_FIELD_SANDBOX.split(' ').sort()).toEqual(['allow-same-origin', 'allow-scripts']);
  });

  it('grants nothing that would let the field act on the host page', () => {
    for (const forbidden of [
      'allow-forms',
      'allow-popups',
      'allow-popups-to-escape-sandbox',
      'allow-top-navigation',
      'allow-top-navigation-by-user-activation',
      'allow-modals',
      'allow-downloads',
      'allow-presentation',
      'allow-pointer-lock',
    ]) {
      expect(SECURE_FIELD_SANDBOX.includes(forbidden), `sandbox grants ${forbidden}`).toBe(false);
    }
  });
});

describe('mountSecureField refuses a credential that is not a capability token', () => {
  const container = { ownerDocument: { createElement: () => { throw new Error('must not reach the DOM'); } } } as any;

  for (const bad of ['', 'tk_live_something', 'sk_live_something', 'Bearer kct_x', 'kc:1:s:x:$']) {
    it(`refuses ${JSON.stringify(bad)} before building an iframe`, () => {
      expect(() => mountSecureField(container, { format: 'pan', capabilityToken: bad })).toThrow(/kct_/);
    });
  }
});
