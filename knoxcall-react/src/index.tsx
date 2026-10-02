// @knoxcall/react — hosted fields for React (Card-Grade Vaults A3).
//
// `<SecureField>` embeds a KnoxCall-served iframe that captures ONE sensitive
// value — a card number, an SSN, a bank account, an email, anything — and
// exchanges it for a VAULT TOKEN without the value ever entering your page's
// JavaScript, your bundle, or your backend. Your `onToken` callback receives
// the token and display-safe metadata (`last4`, `brand`), never the value and
// never a ciphertext you could mishandle.
//
// The flow, end to end:
//
//   1. YOUR BACKEND mints a single-use capability token with its ordinary API
//      credentials, naming the vault and the exact page origins it may be used
//      from:  POST /v1/client-tokens {action:'tokenize', vault, origins}
//   2. YOUR PAGE renders <SecureField capabilityToken={…} format="pan" />.
//   3. THE CUSTOMER types into the iframe. Nothing crosses into your page but a
//      `complete` boolean and, for cards, a brand and last four.
//   4. YOU call `tokenize()` on submit. The iframe posts the value straight to
//      KnoxCall and hands you back the vault token.
//
// The capability is single-use and expires in five minutes, so there is no
// long-lived secret in the page and nothing worth stealing from it.
//
// SECURITY MODEL. Every inbound `message` is origin-checked (exact string),
// source-checked (must be OUR iframe's window) and shape-validated before it is
// trusted, by the shared, unit-tested protocol in `@knoxcall/browser`. Outbound
// messages carry an explicit `targetOrigin`, never `'*'`.

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  mountSecureField,
  DEFAULT_ELEMENT_BASE,
  DEFAULT_ELEMENT_ORIGINS,
  KNOX_MESSAGE,
  isTrustedElementOrigin,
  parseKnoxMessage,
  type KnoxChangeMessage,
  type KnoxErrorMessage,
  type KnoxFieldFormat,
  type KnoxFieldStyle,
  type KnoxReadyMessage,
  type KnoxTokenMessage,
  type SecureFieldHandle,
} from '@knoxcall/browser';

export type {
  KnoxChangeMessage,
  KnoxErrorMessage,
  KnoxFieldFormat,
  KnoxFieldStyle,
  KnoxReadyMessage,
  KnoxTokenMessage,
};

export interface SecureFieldProps {
  /**
   * Which inputs to render — a HINT, honoured only where the bound vault's own
   * format admits that layout; `onReady` reports what was actually drawn. The
   * VAULT's real format is enforced server-side, and is what decides whether
   * `last4`/`brand`/`exp_month`/`exp_year` reach this page at all.
   */
  format: KnoxFieldFormat;
  /** The single-use `kct_` capability token your backend minted. */
  capabilityToken: string;
  /**
   * The vault this field tokenizes into.
   *
   * DISPLAY AND ASSERTION ONLY — the binding that matters is the one inside the
   * capability token, chosen by your backend. Passing it here lets your own
   * code and tests state the intent; nothing the page sends can change which
   * vault the value lands in.
   */
  vault?: string;
  /** Where the hosted-fields page is served from. Override with `origins`. */
  elementBase?: string;
  /**
   * Trusted origins for inbound messages. Defaults to the production elements
   * origin, and MUST be overridden together with `elementBase` — otherwise every
   * message from your own iframe is discarded and the field never reports ready.
   */
  origins?: string[];
  /** A constrained style object. Unknown keys and invalid values are ignored. */
  fieldStyle?: KnoxFieldStyle;
  /** Style for the iframe ELEMENT itself (layout), not its contents. */
  style?: React.CSSProperties;
  className?: string;
  title?: string;
  onReady?: (msg: KnoxReadyMessage) => void;
  onChange?: (msg: KnoxChangeMessage) => void;
  onToken?: (msg: KnoxTokenMessage) => void;
  onError?: (msg: KnoxErrorMessage) => void;
}

export interface SecureFieldRef {
  /** Ask the field to tokenize. Resolves through `onToken` / `onError`. */
  tokenize(): void;
  /** Push a new style object into the field. */
  setStyle(style: KnoxFieldStyle): void;
}

/**
 * The hosted field.
 *
 * Use the `ref` (or `useSecureField()`) to call `tokenize()` on submit.
 * Tokenizing is DELIBERATELY not triggered by a `change` event: the prototype
 * this replaces sealed on the card-number field's `change`, once every field was
 * complete — so a customer typing number → expiry → CVC, the natural order,
 * never produced a token at all.
 */
export const SecureField = React.forwardRef<SecureFieldRef, SecureFieldProps>(
  function SecureField(props, ref) {
    const container = useRef<HTMLDivElement>(null);
    const handle = useRef<SecureFieldHandle | null>(null);
    // Callbacks live in a ref so a parent that re-creates them inline does not
    // tear the iframe down and back up on every render — which would lose
    // whatever the customer had typed.
    const callbacks = useRef(props);
    callbacks.current = props;

    const origins = props.origins ?? DEFAULT_ELEMENT_ORIGINS;
    const originKey = origins.join('|');

    useEffect(() => {
      const node = container.current;
      if (!node) return;
      const field = mountSecureField(node, {
        format: props.format,
        capabilityToken: props.capabilityToken,
        elementBase: props.elementBase,
        origins,
        style: callbacks.current.fieldStyle,
        title: props.title,
        onReady: (m) => callbacks.current.onReady?.(m),
        onChange: (m) => callbacks.current.onChange?.(m),
        onToken: (m) => callbacks.current.onToken?.(m),
        onError: (m) => callbacks.current.onError?.(m),
      });
      handle.current = field;
      return () => {
        field.destroy();
        handle.current = null;
      };
      // The iframe is re-created only when its IDENTITY changes: a different
      // capability, format, base or origin list is a different field.
    }, [props.format, props.capabilityToken, props.elementBase, originKey, props.title]);

    React.useImperativeHandle(ref, () => ({
      tokenize: () => handle.current?.tokenize(),
      setStyle: (style: KnoxFieldStyle) => handle.current?.setStyle(style),
    }), []);

    return <div ref={container} className={props.className} style={props.style} />;
  },
);

export interface UseSecureFieldResult {
  /** Pass to `<SecureField ref={…}>`. */
  ref: React.RefObject<SecureFieldRef | null>;
  /** Ask the field to tokenize. */
  tokenize: () => void;
  /** True once every input in the field is valid. */
  complete: boolean;
  /** The last error the field reported, or null. */
  error: KnoxErrorMessage | null;
  /** The last token the field produced, or null. */
  token: KnoxTokenMessage | null;
  /** Wire these into `<SecureField {...handlers} />`. */
  handlers: Pick<SecureFieldProps, 'onChange' | 'onError' | 'onToken'>;
}

/**
 * The state a checkout actually needs around a hosted field: a `tokenize()` to
 * call on submit, whether the field is `complete` (to enable the button), the
 * last error, and the token once it arrives.
 *
 * Compose your own `onChange`/`onError`/`onToken` on top by passing them in —
 * they run after this hook's own state update, never instead of it.
 */
export function useSecureField(
  props: Pick<SecureFieldProps, 'onChange' | 'onError' | 'onToken'> = {},
): UseSecureFieldResult {
  const ref = useRef<SecureFieldRef | null>(null);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState<KnoxErrorMessage | null>(null);
  const [token, setToken] = useState<KnoxTokenMessage | null>(null);

  const outer = useRef(props);
  outer.current = props;

  const onChange = useCallback((msg: KnoxChangeMessage) => {
    setComplete(msg.complete);
    outer.current.onChange?.(msg);
  }, []);
  const onError = useCallback((msg: KnoxErrorMessage) => {
    setError(msg);
    outer.current.onError?.(msg);
  }, []);
  const onToken = useCallback((msg: KnoxTokenMessage) => {
    setError(null);
    setToken(msg);
    outer.current.onToken?.(msg);
  }, []);

  const tokenize = useCallback(() => { ref.current?.tokenize(); }, []);
  const handlers = useMemo(() => ({ onChange, onError, onToken }), [onChange, onError, onToken]);

  return { ref, tokenize, complete, error, token, handlers };
}

// ── Reveal ──────────────────────────────────────────────────────────────────

export interface RevealProps {
  /** Single-use capability token minted by your backend. */
  capabilityToken: string;
  /** The kc: ciphertext (or vault token) to reveal. */
  ciphertext: string;
  /** 'decrypt' for kc: values, 'detokenize' for vault tokens. */
  action?: 'decrypt' | 'detokenize';
  elementBase?: string;
  origins?: string[];
  className?: string;
  style?: React.CSSProperties;
  onError?: (message: string) => void;
}

/**
 * UNFINISHED: the reveal page is not served. `<Reveal>` points at
 * `{elementBase}/reveal`, and the hosted-fields origin (Card-Grade Vaults A2)
 * serves `/field` and its script and 404s everything else — so this component
 * renders an iframe that does not load. It is exported, and left in the package,
 * because the CAPTURE direction shipped first by design and removing the export
 * would be a breaking change to a name that is already documented; it is
 * excluded from the README for the same reason it is marked here.
 *
 * What it needs: a reveal page on the elements origin that consumes a
 * `decrypt`/`detokenize` capability inside the iframe and displays the plaintext
 * without it crossing into host JavaScript. The capability tokens for both
 * actions already exist (`POST /v1/client-tokens`), and `KnoxClient.reveal()` /
 * `KnoxClient.detokenize()` in `@knoxcall/browser` are the same exchange done
 * IN the host page — which is the thing this component exists to avoid, so it
 * is not a substitute.
 *
 * Do not build on this until the page exists.
 */
export function Reveal(props: RevealProps): React.ReactElement {
  const origins = props.origins ?? DEFAULT_ELEMENT_ORIGINS;
  const action = props.action ?? 'decrypt';
  const base = (props.elementBase ?? DEFAULT_ELEMENT_BASE).replace(/\/$/, '');
  const src = `${base}/reveal`;
  const ref = useRef<HTMLIFrameElement>(null);
  const cbs = useRef(props);
  cbs.current = props;

  useEffect(() => {
    const targetOrigin = new URL(src).origin;
    function handler(e: MessageEvent) {
      if (!isTrustedElementOrigin(e.origin, origins)) return;
      if (!ref.current || e.source !== ref.current.contentWindow) return;
      const msg = parseKnoxMessage(e.data);
      if (!msg) return;
      if (msg.type === KNOX_MESSAGE.READY) {
        ref.current.contentWindow?.postMessage(
          { type: 'knox:reveal', token: cbs.current.capabilityToken, ciphertext: cbs.current.ciphertext, action },
          targetOrigin,
        );
      } else if (msg.type === KNOX_MESSAGE.ERROR) {
        cbs.current.onError?.(msg.message);
      }
    }
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, [src, origins.join('|'), action]);

  return (
    <iframe
      ref={ref}
      src={src}
      title="Revealed value"
      sandbox="allow-scripts allow-same-origin"
      className={props.className}
      style={{ border: 'none', width: '100%', ...props.style }}
    />
  );
}
