// @knoxcall/browser — the hosted-fields ("Elements") postMessage protocol,
// PARENT side.
//
// A KnoxCall hosted field runs inside a cross-origin iframe served from
// `elements.knoxcall.com`. The value the customer types — a card number, an
// SSN, a bank account — lives in that document and leaves it exactly once, in
// the body of one `POST /v1/client/tokenize`. Your page never sees it, and
// neither does an XSS on your page: the callbacks here receive a VAULT TOKEN and
// display-safe metadata (`last4`, `brand`), never the value and never a
// ciphertext.
//
// This module is pure — no DOM — so the security-critical halves (message-shape
// validation and origin checking) are unit-testable, and `secure-field.ts`
// builds the DOM plumbing on top of it.
//
// TRUST RULE FOR ANY CONSUMER WRITING ITS OWN PLUMBING. Three checks, all
// required, in this order:
//
//   1. `event.origin` is one of the KnoxCall element origins
//      (`isTrustedElementOrigin` — EXACT string match, never a prefix);
//   2. `event.source` is YOUR iframe's `contentWindow` — a same-origin check
//      does not cover a different WINDOW at the same origin;
//   3. `parseKnoxMessage` returns non-null.
//
// Shape validation alone is not sufficient, and neither is the origin check
// alone. `secure-field.ts` and `@knoxcall/react` do all three.
//
// ── THE GRAMMAR HAS A SECOND COPY, AND IT IS PINNED ─────────────────────────
// The iframe's half lives at `src/card-service/elements/protocol.ts` in the KnoxCall server
// repository, because this package must be publishable without it and that
// module must be bundleable into the page. `tests/elements-protocol-parity.test.ts`
// there imports BOTH and asserts the message-type constants are identical and
// that each side accepts exactly what the other emits.

export const KNOX_MESSAGE = {
  // parent → iframe
  TOKENIZE: 'knox:tokenize',
  STYLE: 'knox:style',
  // iframe → parent
  READY: 'knox:ready',
  CHANGE: 'knox:change',
  TOKEN: 'knox:token',
  ERROR: 'knox:error',
} as const;

/**
 * Error codes the iframe emits — a CLOSED SET, so you can branch on the code
 * rather than string-matching a message written for a human.
 *
 *   incomplete               a `tokenize()` before every field is valid
 *   invalid_token            the capability was unknown, expired, already used,
 *                            or not bound to this page's origin. All four are
 *                            one code on purpose (the server answers one 401),
 *                            and the fix is always the same: mint a new one.
 *   origin_required          the request reached us without an `Origin` header
 *   card_program_unavailable a `pan` vault while KnoxCall holds no current PCI
 *                            DSS Attestation of Compliance — see the README
 *   tokenize_failed          the value was refused by the vault's own format
 *   network_error            the request never completed
 *   session_expired          the iframe has no capability token at all
 */
export const KNOX_ERROR_CODES = [
  'incomplete',
  'invalid_token',
  'origin_required',
  'card_program_unavailable',
  'tokenize_failed',
  'network_error',
  'session_expired',
] as const;
export type KnoxErrorCode = (typeof KNOX_ERROR_CODES)[number];

/** The field layouts a hosted field can render. */
export const KNOX_FIELD_FORMATS = ['pan', 'ssn', 'bank_account', 'email', 'generic'] as const;
export type KnoxFieldFormat = (typeof KNOX_FIELD_FORMATS)[number];

// ── parent → iframe ─────────────────────────────────────────────────────────

export interface KnoxTokenizeMessage { type: typeof KNOX_MESSAGE.TOKENIZE; }
export interface KnoxStyleMessage {
  type: typeof KNOX_MESSAGE.STYLE;
  style: Record<string, unknown>;
}
export type KnoxParentMessage = KnoxTokenizeMessage | KnoxStyleMessage;

// ── iframe → parent ─────────────────────────────────────────────────────────

export interface KnoxReadyMessage { type: typeof KNOX_MESSAGE.READY; format: string; }
export interface KnoxChangeMessage {
  type: typeof KNOX_MESSAGE.CHANGE;
  complete: boolean;
  brand?: string;
  last4?: string;
}
export interface KnoxTokenMessage {
  type: typeof KNOX_MESSAGE.TOKEN;
  /** The VAULT token. Store this; the proxy resolves it later. */
  token: string;
  /** The vault-token row id, for metadata updates and audit correlation. */
  id: string;
  /** ISO timestamp, or null when the vault sets no TTL. */
  expires_at: string | null;
  last4?: string;
  brand?: string;
  exp_month?: number;
  exp_year?: number;
}
export interface KnoxErrorMessage {
  type: typeof KNOX_MESSAGE.ERROR;
  code: KnoxErrorCode;
  message: string;
}

export type KnoxElementMessage =
  | KnoxReadyMessage | KnoxChangeMessage | KnoxTokenMessage | KnoxErrorMessage;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Validate + narrow an untrusted postMessage payload into a message the IFRAME
 * may send. Returns null for anything else, so a page sharing the window with
 * other postMessage traffic ignores foreign messages — and so a hostile page
 * cannot drive your callbacks by echoing a parent→iframe type back at you.
 */
export function parseKnoxMessage(data: unknown): KnoxElementMessage | null {
  if (!isObj(data) || typeof data.type !== 'string') return null;
  switch (data.type) {
    case KNOX_MESSAGE.READY:
      if (typeof data.format !== 'string') return null;
      return { type: KNOX_MESSAGE.READY, format: data.format };
    case KNOX_MESSAGE.CHANGE:
      if (typeof data.complete !== 'boolean') return null;
      return {
        type: KNOX_MESSAGE.CHANGE,
        complete: data.complete,
        brand: typeof data.brand === 'string' ? data.brand : undefined,
        last4: typeof data.last4 === 'string' ? data.last4 : undefined,
      };
    case KNOX_MESSAGE.TOKEN:
      // `token` and `id` are REQUIRED. A "token" message with no token would
      // otherwise reach `onToken` as `undefined` and be stored as the customer's
      // payment instrument.
      if (typeof data.token !== 'string' || data.token.length === 0) return null;
      if (typeof data.id !== 'string' || data.id.length === 0) return null;
      if (data.expires_at !== null && typeof data.expires_at !== 'string') return null;
      return {
        type: KNOX_MESSAGE.TOKEN,
        token: data.token,
        id: data.id,
        expires_at: (data.expires_at as string | null) ?? null,
        last4: typeof data.last4 === 'string' ? data.last4 : undefined,
        brand: typeof data.brand === 'string' ? data.brand : undefined,
        exp_month: typeof data.exp_month === 'number' ? data.exp_month : undefined,
        exp_year: typeof data.exp_year === 'number' ? data.exp_year : undefined,
      };
    case KNOX_MESSAGE.ERROR: {
      const code = (KNOX_ERROR_CODES as readonly string[]).includes(String(data.code))
        ? (data.code as KnoxErrorCode)
        : 'tokenize_failed';
      return {
        type: KNOX_MESSAGE.ERROR,
        code,
        message: typeof data.message === 'string' ? data.message : 'unknown error',
      };
    }
    default:
      return null;
  }
}

/**
 * True when `origin` is one of the allowed KnoxCall element origins.
 *
 * EXACT string match only. `https://elements.knoxcall.com.evil.com` starts with
 * everything we own and ends with nothing we own, so a prefix or suffix test
 * here is the whole bypass.
 */
export function isTrustedElementOrigin(origin: string, allowed: string[]): boolean {
  return allowed.includes(origin);
}

/** Where the hosted-fields page is served from. */
export const DEFAULT_ELEMENT_BASE = 'https://elements.knoxcall.com';

/**
 * Default trusted element origins.
 *
 * If you override `elementBase` (a self-hosted install, a staging environment),
 * you MUST override `origins` to match — otherwise every message from your own
 * iframe is discarded by the origin check, and the field will look like it never
 * loads. That is the safe failure, and it is deliberate: a default that widened
 * itself to whatever `elementBase` said would trust a base somebody else set.
 */
export const DEFAULT_ELEMENT_ORIGINS = [DEFAULT_ELEMENT_BASE];
