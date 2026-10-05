import { createSecretKey, type KeyObject } from "crypto";

// The two things every E2EE module and both repositories have to agree on: the
// envelope version, and the four rejection codes.
//
// They live here rather than in a route module because the record layer imports
// them, and `record.ts` importing `api/routes/misc.routes.ts` would invert the
// dependency direction — a crypto primitive would pull in Hono, the push
// repository and the update config to learn the number `1`
// (specs/end-to-end-encryption/NONCE-DESIGN.md §4).

/**
 * Envelope version this build speaks.
 *
 * The single canonical copy. It is the `version` byte of every record's AAD
 * (NONCE-DESIGN §4), the `v` of `/api/pair/exchange`'s and `/api/e2ee/open`'s
 * `e2ee` field, and the `version` reported by `GET /api/info`.
 *
 * There were two hand-synced copies of this number — `E2EE_PROTOCOL_VERSION` in
 * `api/routes/misc.routes.ts` and `E2EE_EXCHANGE_VERSION` in `pair-request.ts`,
 * kept equal by a comment. W1a collapsed them into this one rather than adding
 * a third: a version that can disagree with itself is a version that eventually
 * does, and the failure ("decryption failed") points nowhere near the cause.
 */
export const E2EE_PROTOCOL_VERSION = 1;

/**
 * The four rejection codes, FROZEN at W1a's tag (NONCE-DESIGN §9).
 *
 * tb-mobile consumes these strings. Renaming one is a coordinated change in
 * both repositories, not a refactor.
 *
 * The distinctions are the point, and each one was chosen because collapsing it
 * would tell a client the wrong thing:
 *
 * - `E2EE_CTX_UNKNOWN` is **recoverable**. The context is unknown, expired, or
 *   was lost to a streamer restart. The client re-handshakes once and retries.
 * - `E2EE_DEVICE_REVOKED` is a **hard failure**. Surface it; never retry.
 *   "Absent" and "invalid" are different answers, and a restart the client can
 *   silently recover from must never look like a revocation it must surface.
 * - `E2EE_SEQUENCE_VIOLATION` is a **claim about the peer**: a repeat, a gap or
 *   a reorder on a channel where none of the three is possible. It is the
 *   WebSocket close reason, so a client can tell a policy close from a drop.
 * - `E2EE_SEAL_FAILED` is a **server-side fault** — it could not seal or unseal
 *   a frame it should have been able to. Deliberately not the same code as a
 *   sequence violation: collapsing them tells a client its own frames were
 *   wrong when the server was at fault, and two failures behind one code was a
 *   P1 in the prior program.
 */
export const E2EE_CTX_UNKNOWN = "E2EE_CTX_UNKNOWN";
export const E2EE_DEVICE_REVOKED = "E2EE_DEVICE_REVOKED";
export const E2EE_SEQUENCE_VIOLATION = "E2EE_SEQUENCE_VIOLATION";
export const E2EE_SEAL_FAILED = "E2EE_SEAL_FAILED";

export type E2eeRejectionCode =
  | typeof E2EE_CTX_UNKNOWN
  | typeof E2EE_DEVICE_REVOKED
  | typeof E2EE_SEQUENCE_VIOLATION
  | typeof E2EE_SEAL_FAILED;

/** Every frozen code, for a test that asserts the set has not drifted. */
export const E2EE_REJECTION_CODES: readonly E2eeRejectionCode[] = [
  E2EE_CTX_UNKNOWN,
  E2EE_DEVICE_REVOKED,
  E2EE_SEQUENCE_VIOLATION,
  E2EE_SEAL_FAILED,
];

/**
 * Install a readable `util.inspect` summary on an object that holds key
 * material.
 *
 * **This is for legibility, not for secrecy.** The keys themselves are
 * ECMAScript `#private` fields, which are not properties at all: invisible to
 * `showHidden`, to `customInspect: false`, to `Object.getOwnPropertyDescriptors`,
 * to spread and to `structuredClone`. That is what makes them safe against a
 * rendering mode nobody thought of.
 *
 * The history is the argument. Hiding rested first on
 * `defineProperty(enumerable: false)` — beaten by `{ showHidden: true }` — and
 * then on this handler — beaten by `{ customInspect: false }`. Together the two
 * flags rendered every traffic key in the process, and on the context registry
 * that was every live context's key in one call. Three defeats of the same
 * approach is the approach being wrong, so secrecy moved into the language and
 * this stayed only to keep a dump readable.
 *
 * Summaries print SHAPE — lengths, counts, counters — and never bytes, not even
 * a prefix.
 */
export function redactKeyMaterial(target: object, summary: () => string): void {
  Object.defineProperty(target, Symbol.for("nodejs.util.inspect.custom"), {
    enumerable: false,
    value: summary,
  });
}

/**
 * Read an optional argument from the ARGUMENT, never from the prototype chain.
 *
 * `args.x ?? fallback` and `args.x || fallback` both walk the prototype chain,
 * so a single `Object.prototype.x = …` anywhere in the process — a dependency's
 * bad day, a test helper, a JSON parse into a bare object — silently supplies a
 * value that no caller passed. On this module that is not a nuisance: a
 * polluted `prologue` collapses §11's domain separation and lets a pairing
 * message be read as an `/open` one, and a polluted `ephemeral` pins every
 * handshake to one attacker-chosen `e`, which by §8's own rule is definitionally
 * a replay.
 *
 * `Object.hasOwn` asks the object and nothing above it.
 */
export function own<T, K extends keyof T>(args: T, key: K): T[K] | undefined {
  return Object.hasOwn(args as object, key as PropertyKey) ? args[key] : undefined;
}

/**
 * The one byte-length guard, used for every fixed-width secret and handle.
 *
 * **`.length` is not byte length for a typed array.** `new Float64Array(32)`
 * has `.length === 32` and `byteLength === 256`, so a `psk.length !== 32` check
 * accepted it and completed a full `IKpsk1` handshake binding 256 zero bytes —
 * a binding over a constant, which is exactly what §11 rejected, reached
 * through a guard rather than a decision. A 32-character string passes a
 * `.length` check too and is not bytes at all.
 *
 * So the check is: a real byte array (`Uint8Array`, which `Buffer` extends),
 * one byte per element, and exactly the expected `byteLength`.
 *
 * The predicate narrows to `Uint8Array`, NOT to `Buffer`. A `Buffer` is one
 * kind of byte view; a client built on `@stablelib` hands over plain
 * `Uint8Array`s, and §13 says that client calls the AAD builder directly. While
 * this said `value is Buffer`, a correct-length plain view passed the guard and
 * then died inside the builder on `target.copy is not a function` — a
 * `TypeError` outside §9's taxonomy, for input that was right.
 *
 * The thrower is a parameter because each module owns its error type and its
 * rejection code; a shared error class here would flatten `RecordError`'s codes
 * into something no caller can act on.
 */
export function isBytes(value: unknown, length: number): value is Uint8Array {
  return (
    value instanceof Uint8Array && value.BYTES_PER_ELEMENT === 1 && value.byteLength === length
  );
}

export function assertBytes(
  value: unknown,
  length: number,
  name: string,
  fail: (message: string) => Error,
): asserts value is Uint8Array {
  if (!isBytes(value, length)) {
    throw fail(`${name} must be exactly ${length} bytes`);
  }
}

/**
 * A copy that shares no allocation with anything else.
 *
 * `Buffer.allocUnsafe`, `Buffer.from(string)` and `Buffer.concat` all carve out
 * of Node's shared 8 KiB pool, and a Buffer's `.buffer`/`byteOffset` expose that
 * whole pool. So a PUBLIC buffer allocated near a secret one hands the secret to
 * anyone who walks it — which is how the context registry printed live traffic
 * keys through `ctxIdRaw`, without touching a key-bearing class at all.
 * `#private` closes nothing when a private buffer shares an allocation with a
 * public one.
 *
 * `allocUnsafeSlow` allocates outside the pool, so a public buffer made this way
 * neighbours nothing.
 */
export function unpooled(source: Uint8Array): Buffer {
  const copy = Buffer.allocUnsafeSlow(source.byteLength);
  copy.set(source);
  return copy;
}

/**
 * Import secret bytes into a `KeyObject` and wipe the JS-heap copy.
 *
 * A `KeyObject`'s material lives in OpenSSL's memory, not on the JS heap: there
 * is no property to render, no pool to walk, and nothing for a serializer to
 * reach. `createCipheriv`/`createDecipheriv` take one directly, so the bytes
 * never need to come back.
 *
 * The intermediate copy is unpooled and zeroed immediately, so the window in
 * which the key exists as JS-visible bytes is this function's body.
 */
export function importSecret(bytes: Uint8Array): KeyObject {
  const copy = unpooled(bytes);
  try {
    return createSecretKey(copy);
  } finally {
    copy.fill(0);
  }
}
