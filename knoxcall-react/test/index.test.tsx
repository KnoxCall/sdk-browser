// <SecureField> / useSecureField — the parent side of the hosted-fields
// protocol, driven through jsdom.
//
// The three checks that make this component worth having are the ones under
// test: every inbound `message` must come from a TRUSTED ORIGIN (exact string),
// from OUR IFRAME'S WINDOW, and in a VALID SHAPE. Each is defeated
// independently below, because each alone is bypassable:
//
//   * a message from the right origin but a different window is a stored-XSS
//     on the merchant's own checkout — the exact threat the iframe exists to
//     survive, and the one an origin check cannot see;
//   * a message from our iframe but an origin like
//     `https://elements.knoxcall.com.evil.com` is the prefix/suffix bypass;
//   * a well-shaped `knox:token` with no `token` would reach `onToken` as
//     `undefined` and be stored as the customer's payment instrument.
//
// Outbound messages are asserted too: `tokenize()` must post to the iframe's
// exact origin, never `'*'`.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import React from 'react';
import {
  SecureField,
  Reveal,
  useSecureField,
  type SecureFieldProps,
  type SecureFieldRef,
} from '../src/index';

const ELEMENT_ORIGIN = 'https://elements.knoxcall.com';
const TOKEN = 'kct_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';
const VAULT_TOKEN = '4111110000001111';
const ROW = '66666666-6666-4666-8666-666666666666';

afterEach(() => {
  cleanup();
  document.body.innerHTML = '';
});

function renderField(props: Partial<SecureFieldProps> = {}) {
  const onReady = vi.fn();
  const onChange = vi.fn();
  const onToken = vi.fn();
  const onError = vi.fn();
  const ref = React.createRef<SecureFieldRef>();
  const utils = render(
    <SecureField
      ref={ref}
      format="pan"
      capabilityToken={TOKEN}
      onReady={onReady}
      onChange={onChange}
      onToken={onToken}
      onError={onError}
      {...props}
    />,
  );
  const iframe = utils.container.querySelector('iframe') as HTMLIFrameElement;
  return { ...utils, iframe, ref, onReady, onChange, onToken, onError };
}

function say(data: unknown, origin: string, source: Window | null) {
  fireEvent(
    window,
    new MessageEvent('message', { data, origin, source: source as MessageEventSource | null }),
  );
}

function strayWindow(): Window {
  const stray = document.createElement('iframe');
  document.body.appendChild(stray);
  return stray.contentWindow as Window;
}

describe('<SecureField> renders a locked-down iframe', () => {
  it('points at /field on the default elements origin with the token and format', () => {
    const { iframe } = renderField({ format: 'ssn' });
    const url = new URL(iframe.src);
    expect(url.origin).toBe(ELEMENT_ORIGIN);
    expect(url.pathname).toBe('/field');
    expect(url.searchParams.get('t')).toBe(TOKEN);
    expect(url.searchParams.get('format')).toBe('ssn');
  });

  it('carries the sandbox attribute, and grants nothing that touches the host page', () => {
    const { iframe } = renderField();
    const sandbox = iframe.getAttribute('sandbox') ?? '';
    expect(sandbox.split(' ').sort()).toEqual(['allow-same-origin', 'allow-scripts']);
    expect(sandbox).not.toContain('allow-top-navigation');
    expect(sandbox).not.toContain('allow-popups');
    expect(sandbox).not.toContain('allow-forms');
  });

  it('refuses to mount with something that is not a capability token', () => {
    // React surfaces the throw from the effect; the point is that no iframe
    // carrying the credential in a URL is ever created.
    expect(() =>
      render(<SecureField format="pan" capabilityToken="tk_live_not_a_capability" />),
    ).toThrow(/kct_/);
  });

  it('honours elementBase together with origins', () => {
    const { iframe } = renderField({
      elementBase: 'https://elements-staging.knoxcall.com',
      origins: ['https://elements-staging.knoxcall.com'],
    });
    expect(new URL(iframe.src).origin).toBe('https://elements-staging.knoxcall.com');
  });
});

describe('inbound messages: origin, source, and shape', () => {
  it('delivers a well-formed message from OUR iframe at a trusted origin', () => {
    const { iframe, onReady, onChange, onToken } = renderField();
    say({ type: 'knox:ready', format: 'pan' }, ELEMENT_ORIGIN, iframe.contentWindow);
    expect(onReady).toHaveBeenCalledWith({ type: 'knox:ready', format: 'pan' });

    say({ type: 'knox:change', complete: true, brand: 'visa', last4: '1111' }, ELEMENT_ORIGIN, iframe.contentWindow);
    expect(onChange).toHaveBeenCalledWith(
      { type: 'knox:change', complete: true, brand: 'visa', last4: '1111' },
    );

    say(
      { type: 'knox:token', token: VAULT_TOKEN, id: ROW, expires_at: null, last4: '1111', brand: 'visa' },
      ELEMENT_ORIGIN,
      iframe.contentWindow,
    );
    expect(onToken).toHaveBeenCalledTimes(1);
    expect(onToken.mock.calls[0][0].token).toBe(VAULT_TOKEN);
  });

  it('IGNORES a message from the right origin but the WRONG window', () => {
    // Script on the merchant's own page — same origin as the checkout, a
    // different window from our iframe. This is the case an origin check alone
    // cannot see, and it is the threat model the component exists for.
    const { onToken } = renderField();
    say(
      { type: 'knox:token', token: 'attacker-token', id: ROW, expires_at: null },
      ELEMENT_ORIGIN,
      strayWindow(),
    );
    expect(onToken).not.toHaveBeenCalled();
  });

  it('IGNORES a message with no source at all', () => {
    const { onToken } = renderField();
    say({ type: 'knox:token', token: 'attacker-token', id: ROW, expires_at: null }, ELEMENT_ORIGIN, null);
    expect(onToken).not.toHaveBeenCalled();
  });

  it('IGNORES a message from our iframe at a LOOKALIKE origin', () => {
    const { iframe, onToken, onError } = renderField();
    for (const origin of [
      'https://elements.knoxcall.com.evil.com',
      'https://elements.knoxcall.com.evil.com:8443',
      'http://elements.knoxcall.com',
      'https://elements.knoxcall.com/',
      'https://xelements.knoxcall.com',
      'https://sub.elements.knoxcall.com',
      'null',
      '',
    ]) {
      say({ type: 'knox:token', token: 'attacker-token', id: ROW, expires_at: null }, origin, iframe.contentWindow);
      say({ type: 'knox:error', code: 'invalid_token', message: 'x' }, origin, iframe.contentWindow);
    }
    expect(onToken).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  it('IGNORES a knox:token with no token — it would be stored as the payment instrument', () => {
    const { iframe, onToken } = renderField();
    say({ type: 'knox:token', id: ROW, expires_at: null }, ELEMENT_ORIGIN, iframe.contentWindow);
    say({ type: 'knox:token', token: '', id: ROW, expires_at: null }, ELEMENT_ORIGIN, iframe.contentWindow);
    say({ type: 'knox:token', token: VAULT_TOKEN, expires_at: null }, ELEMENT_ORIGIN, iframe.contentWindow);
    expect(onToken).not.toHaveBeenCalled();
  });

  it('IGNORES foreign postMessage traffic sharing the window', () => {
    const { iframe, onToken, onChange, onReady } = renderField();
    for (const junk of [null, 42, 'knox:ready', {}, [], { type: 'stripe:token' }, { type: 'knox:unknown' }]) {
      say(junk, ELEMENT_ORIGIN, iframe.contentWindow);
    }
    expect(onToken).not.toHaveBeenCalled();
    expect(onChange).not.toHaveBeenCalled();
    expect(onReady).not.toHaveBeenCalled();
  });

  it('IGNORES a knox:tokenize echoed back at the parent', () => {
    // The iframe never sends this; a page that replayed it must not be able to
    // drive host callbacks through the wrong direction of the protocol.
    const { iframe, onReady, onChange, onToken, onError } = renderField();
    say({ type: 'knox:tokenize' }, ELEMENT_ORIGIN, iframe.contentWindow);
    say({ type: 'knox:style', style: { color: '#fff' } }, ELEMENT_ORIGIN, iframe.contentWindow);
    for (const cb of [onReady, onChange, onToken, onError]) expect(cb).not.toHaveBeenCalled();
  });

  it('stops listening after unmount', () => {
    const { iframe, onToken, unmount } = renderField();
    const win = iframe.contentWindow;
    unmount();
    say({ type: 'knox:token', token: VAULT_TOKEN, id: ROW, expires_at: null }, ELEMENT_ORIGIN, win);
    expect(onToken).not.toHaveBeenCalled();
  });
});

describe('outbound messages', () => {
  it('tokenize() posts to the iframe origin, never to a wildcard', () => {
    const { iframe, ref } = renderField();
    const post = vi.fn();
    Object.defineProperty(iframe, 'contentWindow', {
      value: { postMessage: post },
      configurable: true,
    });
    ref.current!.tokenize();
    expect(post).toHaveBeenCalledWith({ type: 'knox:tokenize' }, ELEMENT_ORIGIN);
    expect(post.mock.calls[0][1]).not.toBe('*');
  });

  it('sends the style object only after the iframe says it is ready', () => {
    const { iframe } = renderField({ fieldStyle: { color: '#112233' } });
    const post = vi.fn();
    const realWindow = iframe.contentWindow;
    Object.defineProperty(iframe, 'contentWindow', { value: { postMessage: post }, configurable: true });
    // The gate compares e.source against iframe.contentWindow, which is now the
    // stub — so the ready must claim to come from it.
    say({ type: 'knox:ready', format: 'pan' }, ELEMENT_ORIGIN, iframe.contentWindow as any);
    expect(post).toHaveBeenCalledWith(
      { type: 'knox:style', style: { color: '#112233' } },
      ELEMENT_ORIGIN,
    );
    expect(realWindow).toBeTruthy();
  });

  it('setStyle() pushes a new style object', () => {
    const { iframe, ref } = renderField();
    const post = vi.fn();
    Object.defineProperty(iframe, 'contentWindow', { value: { postMessage: post }, configurable: true });
    ref.current!.setStyle({ fontSize: '18px' });
    expect(post).toHaveBeenCalledWith({ type: 'knox:style', style: { fontSize: '18px' } }, ELEMENT_ORIGIN);
  });
});

describe('useSecureField', () => {
  function Harness({ spy }: { spy: (state: { complete: boolean; token: unknown; error: unknown }) => void }) {
    const field = useSecureField();
    spy({ complete: field.complete, token: field.token, error: field.error });
    return (
      <>
        <SecureField ref={field.ref} format="pan" capabilityToken={TOKEN} {...field.handlers} />
        <button type="button" onClick={field.tokenize} disabled={!field.complete}>Pay</button>
      </>
    );
  }

  it('tracks complete, token and error from the field', () => {
    const spy = vi.fn();
    const utils = render(<Harness spy={spy} />);
    const iframe = utils.container.querySelector('iframe') as HTMLIFrameElement;
    const button = utils.container.querySelector('button') as HTMLButtonElement;

    expect(button.disabled).toBe(true);

    say({ type: 'knox:change', complete: true, brand: 'visa', last4: '1111' }, ELEMENT_ORIGIN, iframe.contentWindow);
    expect(button.disabled).toBe(false);

    say({ type: 'knox:error', code: 'invalid_token', message: 'nope' }, ELEMENT_ORIGIN, iframe.contentWindow);
    expect(spy.mock.calls[spy.mock.calls.length - 1][0].error).toEqual({ type: 'knox:error', code: 'invalid_token', message: 'nope' });

    say({ type: 'knox:token', token: VAULT_TOKEN, id: ROW, expires_at: null }, ELEMENT_ORIGIN, iframe.contentWindow);
    const last = spy.mock.calls[spy.mock.calls.length - 1][0];
    expect((last.token as any).token).toBe(VAULT_TOKEN);
    // A successful token clears the previous error — otherwise a checkout shows
    // a stale failure beside a completed capture.
    expect(last.error).toBeNull();
  });

  it('tokenize() through the hook reaches the iframe', () => {
    const utils = render(<Harness spy={() => {}} />);
    const iframe = utils.container.querySelector('iframe') as HTMLIFrameElement;
    const post = vi.fn();
    Object.defineProperty(iframe, 'contentWindow', { value: { postMessage: post }, configurable: true });
    say({ type: 'knox:change', complete: true }, ELEMENT_ORIGIN, iframe.contentWindow as any);
    (utils.container.querySelector('button') as HTMLButtonElement).click();
    expect(post).toHaveBeenCalledWith({ type: 'knox:tokenize' }, ELEMENT_ORIGIN);
  });
});

describe('<Reveal> is exported but UNFINISHED', () => {
  it('still renders an iframe at /reveal, which nothing serves yet', () => {
    const utils = render(<Reveal capabilityToken={TOKEN} ciphertext="kc:1:s:x:$" />);
    const iframe = utils.container.querySelector('iframe') as HTMLIFrameElement;
    // Pinned so the day the reveal page is built, this test is the thing that
    // says what URL it must answer on.
    expect(new URL(iframe.src).pathname).toBe('/reveal');
    expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-same-origin');
  });

  it('is marked UNFINISHED in the source, with what is missing', async () => {
    // The marker is the contract with the engineering standard: half-built code
    // carries `// UNFINISHED:` naming what is missing. A test rather than a
    // reviewer's memory, because this export ships on npm.
    // `import.meta.url` is an http: URL under jsdom, so the path is resolved
    // from the package root (vitest's cwd) instead.
    const { readFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const src = readFileSync(join(process.cwd(), 'src', 'index.tsx'), 'utf8');
    expect(src).toContain('UNFINISHED:');
    expect(src).toMatch(/UNFINISHED:[\s\S]{0,200}reveal page is not served/);
  });
});
