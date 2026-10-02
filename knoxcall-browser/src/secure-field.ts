// @knoxcall/browser — `mountSecureField`, the framework-free hosted field.
//
//   const field = mountSecureField(document.getElementById('card')!, {
//     format: 'ssn',
//     capabilityToken: tokenFromYourBackend,   // POST /v1/client-tokens
//     onToken: ({ token }) => savePaymentMethod(token),
//   });
//   submitButton.onclick = () => field.tokenize();
//
// `@knoxcall/react`'s `<SecureField>` is a thin wrapper over this, so both
// frameworks share one implementation of the three checks that matter.

import {
  KNOX_MESSAGE,
  isTrustedElementOrigin,
  parseKnoxMessage,
  DEFAULT_ELEMENT_BASE,
  DEFAULT_ELEMENT_ORIGINS,
  type KnoxChangeMessage,
  type KnoxErrorMessage,
  type KnoxFieldFormat,
  type KnoxReadyMessage,
  type KnoxTokenMessage,
} from './elements.js';

/** Style keys a page may set inside the field. Anything else is ignored. */
export interface KnoxFieldStyle {
  color?: string;
  backgroundColor?: string;
  borderColor?: string;
  borderRadius?: string;
  borderWidth?: string;
  fontSize?: string;
  /** One of `system` | `sans` | `serif` | `mono` — a NAME, never a font string. */
  fontFamily?: string;
  lineHeight?: string;
  padding?: string;
  labelColor?: string;
  placeholderColor?: string;
  errorColor?: string;
}

export interface SecureFieldOptions {
  /**
   * Which inputs the iframe renders — a HINT, honoured only where the bound
   * vault's own format admits that layout, and reaching no decision about what
   * the field tells this page. `onReady` reports what was actually drawn. The
   * VAULT's format is what the server enforces, and it is also what gates
   * `last4`/`brand`/`exp_month`/`exp_year`.
   */
  format: KnoxFieldFormat;
  /** A single-use `kct_` capability token minted by YOUR backend. */
  capabilityToken: string;
  /** Where the hosted-fields page is served from. Override with `origins`. */
  elementBase?: string;
  /** Trusted origins for inbound messages. Override together with `elementBase`. */
  origins?: string[];
  style?: KnoxFieldStyle;
  /** Accessible name for the iframe. */
  title?: string;
  className?: string;
  onReady?: (msg: KnoxReadyMessage) => void;
  onChange?: (msg: KnoxChangeMessage) => void;
  onToken?: (msg: KnoxTokenMessage) => void;
  onError?: (msg: KnoxErrorMessage) => void;
}

export type SecureFieldEvent = 'ready' | 'change' | 'token' | 'error';

export interface SecureFieldHandle {
  /** Ask the iframe to tokenize what the customer typed. Fires `token` or `error`. */
  tokenize(): void;
  /** Push a new style object into the iframe. */
  setStyle(style: KnoxFieldStyle): void;
  /** Remove the iframe and the message listener. */
  destroy(): void;
  /** Subscribe to an event; returns an unsubscribe function. */
  on(event: SecureFieldEvent, handler: (msg: any) => void): () => void;
  /** The iframe element, for layout. Do not reach into it — you cannot. */
  readonly iframe: HTMLIFrameElement;
}

/**
 * The iframe `sandbox` attribute, and the justification for every token in it.
 *
 *   allow-scripts       the field script must run; without it the page is inert
 *                       and nothing can be typed or tokenized.
 *   allow-same-origin   REQUIRED, and the one that looks alarming. Without it
 *                       the document gets an OPAQUE origin, and two things
 *                       break: it cannot read its own injected configuration,
 *                       and — decisively — its `POST /v1/client/tokenize` would
 *                       carry `Origin: null`, which the server refuses
 *                       (`origin_required`) because `null` is the origin every
 *                       sandboxed and opaque document on the internet shares.
 *                       The usual warning about `allow-scripts allow-same-origin`
 *                       is that a SAME-ORIGIN frame can then remove its own
 *                       sandbox; this frame is CROSS-origin to your page, so
 *                       `allow-same-origin` restores only its own origin and
 *                       grants it nothing of yours.
 *
 * `allow-forms` is deliberately NOT granted, against the first draft of this
 * component: the page contains no `<form>` and its CSP carries
 * `form-action 'none'`, so granting it would be a capability with no use — and
 * a form POST is the one navigation `connect-src` does not govern.
 * `allow-popups`, `allow-top-navigation` and `allow-modals` are likewise absent:
 * a field that can navigate your checkout away is a phishing primitive.
 */
export const SECURE_FIELD_SANDBOX = 'allow-scripts allow-same-origin';

/** Build the iframe URL. Exported so tests can assert it without a DOM. */
export function secureFieldSrc(opts: {
  elementBase?: string;
  format: KnoxFieldFormat;
  capabilityToken: string;
}): string {
  const base = (opts.elementBase ?? DEFAULT_ELEMENT_BASE).replace(/\/$/, '');
  const params = new URLSearchParams({ t: opts.capabilityToken, format: opts.format });
  return `${base}/field?${params.toString()}`;
}

export function mountSecureField(
  container: HTMLElement,
  opts: SecureFieldOptions,
): SecureFieldHandle {
  if (!opts.capabilityToken || !opts.capabilityToken.startsWith('kct_')) {
    throw new Error('mountSecureField: a client capability token (kct_…) is required');
  }
  const origins = opts.origins ?? DEFAULT_ELEMENT_ORIGINS;
  const src = secureFieldSrc(opts);
  // The ONE origin every outbound message is addressed to. Derived from the
  // `src` we set, never from a message we received.
  const targetOrigin = new URL(src).origin;

  const iframe = container.ownerDocument.createElement('iframe');
  iframe.src = src;
  iframe.title = opts.title ?? 'Secure field';
  iframe.setAttribute('sandbox', SECURE_FIELD_SANDBOX);
  iframe.setAttribute('allow', '');
  iframe.setAttribute('referrerpolicy', 'no-referrer');
  iframe.style.border = 'none';
  iframe.style.width = '100%';
  if (opts.className) iframe.className = opts.className;
  container.appendChild(iframe);

  const listeners: Record<SecureFieldEvent, Set<(msg: any) => void>> = {
    ready: new Set(),
    change: new Set(),
    token: new Set(),
    error: new Set(),
  };
  if (opts.onReady) listeners.ready.add(opts.onReady);
  if (opts.onChange) listeners.change.add(opts.onChange);
  if (opts.onToken) listeners.token.add(opts.onToken);
  if (opts.onError) listeners.error.add(opts.onError);

  function emit(event: SecureFieldEvent, msg: unknown): void {
    for (const handler of listeners[event]) handler(msg);
  }

  function send(message: unknown): void {
    iframe.contentWindow?.postMessage(message, targetOrigin);
  }

  function handler(e: MessageEvent): void {
    // 1. exact origin, 2. OUR iframe's window, 3. a valid message shape.
    if (!isTrustedElementOrigin(e.origin, origins)) return;
    if (!iframe.contentWindow || e.source !== iframe.contentWindow) return;
    const msg = parseKnoxMessage(e.data);
    if (!msg) return;

    switch (msg.type) {
      case KNOX_MESSAGE.READY:
        if (opts.style) send({ type: KNOX_MESSAGE.STYLE, style: opts.style });
        emit('ready', msg);
        break;
      case KNOX_MESSAGE.CHANGE: emit('change', msg); break;
      case KNOX_MESSAGE.TOKEN: emit('token', msg); break;
      case KNOX_MESSAGE.ERROR: emit('error', msg); break;
    }
  }

  const view = container.ownerDocument.defaultView;
  view?.addEventListener('message', handler);

  return {
    iframe,
    tokenize() { send({ type: KNOX_MESSAGE.TOKENIZE }); },
    setStyle(style: KnoxFieldStyle) { send({ type: KNOX_MESSAGE.STYLE, style }); },
    destroy() {
      view?.removeEventListener('message', handler);
      iframe.remove();
      for (const set of Object.values(listeners)) set.clear();
    },
    on(event: SecureFieldEvent, cb: (msg: any) => void) {
      listeners[event].add(cb);
      return () => { listeners[event].delete(cb); };
    },
  };
}
