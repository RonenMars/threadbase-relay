// Noise_IKpsk1_25519_ChaChaPoly_SHA256, written against the Noise Protocol
// Framework specification revision 34.
//
// WHY THIS IS HAND-WRITTEN, since hand-written crypto is normally the wrong
// answer. dilemmas.md D-1 chose the `IK` pattern and named its own flip
// condition: no maintained Noise implementation that works in React Native
// *and* Node without a native module. That condition holds (surveyed
// 2026-08-15 — `noise-protocol` and `noise-handshake` both need
// `sodium-universal`, which Hermes cannot run; the pure-JS alternatives are
// either unmaintained or libp2p-coupled). D-1's prescribed fallback is exactly
// this: an `IK`-shaped exchange written against the spec and reviewed as such,
// never an ad-hoc design.
//
// So: the pattern, the token order, the transcript hash, and the key-mixing
// order are all decided by the specification rather than by us. Nothing here is
// invented. Where the spec offers a choice, the choice is stated in a comment
// with the section it comes from, because "why is it done this way" must be
// answerable without re-deriving the protocol.
//
// The client half lives in tb-mobile over @stablelib. The two implementations
// agree because they are checked against the same committed test vectors
// (`__tests__/fixtures/noise-ikpsk1-vectors.json`), which is the only thing
// that catches a transcript divergence between two independent implementations.
//
//   IKpsk1:
//     <- s                        (pre-message: the QR's `spk`)
//     ...
//     -> e, es, s, ss, psk        (message 1, from the phone)
//     <- e, ee, se                (message 2, from the streamer)
//
// `psk1` places the `psk` token at the END of the first message (spec §9.3), so
// the pair token binds the handshake to *this* QR: completing it proves the
// initiator scanned this code rather than merely that it reached the server.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
} from "crypto";
import { importSecret, isBytes, own, redactKeyMaterial, unpooled } from "./protocol";

export const NOISE_PROTOCOL_NAME = "Noise_IKpsk1_25519_ChaChaPoly_SHA256";

/**
 * The psk-less pattern, used by `POST /api/e2ee/open` (NONCE-DESIGN §11).
 *
 * The transport handshake runs against static keys pairing already stored and
 * has no pair token, so there is no pre-shared secret to mix. A constant public
 * "PSK" was considered and rejected: it reduces to plain `IK` anyway and
 * encodes "there is a PSK here that means nothing", which a reader takes as a
 * freshness guarantee that does not exist.
 *
 * The name is not decoration — it is the string that seeds `h`, so it is itself
 * domain separation: a message from one pattern cannot be read by the other
 * even before the prologue is considered.
 */
export const NOISE_IK_PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_SHA256";

/**
 * Which of the two patterns a handshake call means.
 *
 * **Stated, never inferred.** This used to be decided by whether `psk` was
 * present, which made a forgotten argument select the WEAKER protocol: a
 * pairing call site that omitted its psk would have silently run plain `IK`
 * and lost the pair-token binding that is the entire reason pairing uses
 * `IKpsk1` (spec §9.3, design.md §2.4). A missing argument must never be a
 * downgrade, so the pattern is named and the two are checked against each
 * other in both directions — a psk handed to `IK` is the same caller confusion
 * wearing the other face.
 *
 * The default is the STRONGER pattern, so an un-updated call site that forgets
 * its psk throws instead of quietly weakening.
 */
export type NoisePattern = "IKpsk1" | "IK";

const NOISE_PATTERNS: readonly NoisePattern[] = ["IKpsk1", "IK"];

/**
 * The protocol name for a pattern, or a throw.
 *
 * **Exhaustive, and fail-closed on anything unrecognised.** This used to end in
 * `pattern === "IKpsk1" ? A : B`, so a value that matched neither guard —
 * `"IKPSK1"`, `"ik"`, anything arriving from a config file, a wire field or a
 * client artefact — fell through to psk-less `IK` and silently dropped the
 * pair-token binding. TypeScript rules that out for callers inside this
 * repository; the client track consumes this module as an artefact, and a type
 * is not a runtime check.
 *
 * So there are two layers: a runtime membership test for values that were never
 * typed, and a `never` arm that makes adding a third pattern a compile error
 * here rather than a silent default somewhere else.
 */
/**
 * A prologue is REQUIRED and must be real bytes — of any length, since the two
 * namespace strings differ in length.
 *
 * Not `assertBytes`, which pins a width: this is the presence-and-type half of
 * the same rule. It is a parameter rather than a default because
 * `args.prologue ?? PAIR_PROLOGUE` is a prototype-chain read, and a polluted
 * `Object.prototype.prologue` made the PAIRING handshake accept an `/open`
 * message — §11's domain separation collapsing through a language default
 * nobody wrote.
 */
function assertPrologue(prologue: unknown): asserts prologue is Buffer {
  if (!(prologue instanceof Uint8Array) || prologue.BYTES_PER_ELEMENT !== 1) {
    throw new NoiseError("prologue is required: pass PAIR_PROLOGUE or OPEN_PROLOGUE");
  }
}

function protocolNameFor(pattern: NoisePattern, psk: Buffer | undefined): string {
  if (!NOISE_PATTERNS.includes(pattern)) {
    throw new NoiseError(
      `Unknown Noise pattern ${JSON.stringify(String(pattern))}; expected "IKpsk1" or "IK"`,
    );
  }
  switch (pattern) {
    case "IKpsk1":
      // ONE guard, and it checks BYTE LENGTH.
      //
      // Two versions of this were wrong in the same way. `!psk` accepted
      // `Buffer.alloc(0)`, which is truthy, and completed a full `IKpsk1`
      // handshake over an empty psk. `psk.length !== 32` then accepted
      // `new Float64Array(32)`, whose `.length` is 32 and whose byteLength is
      // 256, binding 256 zero bytes. Both produce the thing §11 rejects — a
      // wire that says `IKpsk1` over a binding that is a constant — and both
      // arrived through a guard rather than a decision.
      //
      // The defect was never in any single guard. It was in writing the guard
      // four times, so `isBytes` is now the only place the question is asked.
      if (!isBytes(psk, HASHLEN)) {
        throw new NoiseError(
          `The IKpsk1 pattern requires a ${HASHLEN}-byte psk; pass one, or pattern: "IK"`,
        );
      }
      return NOISE_PROTOCOL_NAME;
    case "IK":
      if (psk) {
        throw new NoiseError('The IK pattern takes no psk; drop it, or pattern: "IKpsk1"');
      }
      return NOISE_IK_PROTOCOL_NAME;
    default: {
      const unreachable: never = pattern;
      throw new NoiseError(`Unhandled Noise pattern ${String(unreachable)}`);
    }
  }
}

/**
 * Prologue for the PAIRING handshake, mixed into the transcript before any
 * token (spec §5.3, `MixHash(prologue)`).
 *
 * Not in design.md, and added deliberately. The design has two `IK` handshakes:
 * this one at `/api/pair/exchange` with the pair token as PSK, and a later one
 * at `/api/e2ee/open` against stored static keys with no PSK. Without a
 * prologue the two transcripts differ only by the presence of the PSK, so
 * "could a message from one be replayed into the other" becomes a question you
 * answer by reasoning about the PSK. A prologue answers it by construction, and
 * it costs one hash.
 *
 * **`"threadbase-e2ee/<version> <purpose>"` is a namespace, not one string.**
 * Its sibling is `"threadbase-e2ee/1 open"` for `/api/e2ee/open`, named here
 * rather than left for that phase to invent: half a domain separation is a
 * property nobody has, and a convention chosen once with both instances visible
 * is the one that survives a third handshake. The constant itself is not
 * declared until something uses it.
 *
 * Changing this string is a silent, total incompatibility with tb-mobile — it
 * is hashed into `h` before any token, so the only symptom is "decryption
 * failed". It is pinned by a committed vector for that reason.
 */
export const PAIR_PROLOGUE = Buffer.from("threadbase-e2ee/1 pair", "utf-8");

/**
 * The sibling named above, now that `/api/e2ee/open` exists to use it.
 *
 * Same namespace, different purpose, so a message from the pairing handshake
 * can never be replayed into the transport handshake or the other way round —
 * by construction, rather than by an argument about the PSK.
 */
export const OPEN_PROLOGUE = Buffer.from("threadbase-e2ee/1 open", "utf-8");

// The `/open` handshake takes NO psk: pass `pattern: "IK"` to these calls and
// omit `psk`. Omitting `psk` alone is NOT how the pattern is selected — that
// would make a forgotten argument a downgrade — and it throws.

const DHLEN = 32;
const HASHLEN = 32;
const TAGLEN = 16;
/** `e` (32) + `s` sealed (32 + 16) — everything before message 1's payload. */
export const NOISE_MESSAGE_1_OVERHEAD = DHLEN + DHLEN + TAGLEN + TAGLEN;
/**
 * The initiator's ephemeral public key, or `null` when the message is too short
 * to contain one.
 *
 * `e` is the FIRST field of message 1 and travels in the clear (spec §7.4), so
 * it can be read before any Diffie-Hellman — which is what lets
 * `/api/e2ee/open` reject a replayed msg1 without paying for it. Reading it
 * lives here, with the rest of the wire layout, rather than in a route indexing
 * into a buffer by a number it inferred.
 *
 * Returns a VIEW, not a copy: callers must not mutate it.
 */
export function messageEphemeral(message1: Buffer): Buffer | null {
  if (message1.length < NOISE_MESSAGE_1_OVERHEAD) return null;
  return message1.subarray(0, DHLEN);
}

/** `e` (32) — everything before message 2's payload. */
export const NOISE_MESSAGE_2_OVERHEAD = DHLEN + TAGLEN;

/**
 * Cap on a handshake message, checked BEFORE anything is allocated or parsed.
 *
 * The Noise spec's own transport limit is 65535 bytes. This is far below it
 * because our payloads are a handful of JSON fields, and because
 * `/api/pair/exchange` is a public, unauthenticated endpoint — the same
 * reasoning D-9 applies to the unseal middleware, reaching this far forward.
 */
export const NOISE_MAX_MESSAGE_BYTES = 4096;

export class NoiseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoiseError";
  }
}

// ─── X25519 key helpers ─────────────────────────────────────────────
//
// Raw 32-byte keys are what travels; Node's crypto wants KeyObjects. The JWK
// route is the same one server-identity.ts uses, so there is one representation
// of an X25519 key in this codebase rather than two.

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** Raw 32 bytes, which is what goes on the wire. */
  publicKeyRaw: Buffer;
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return { publicKey, privateKey, publicKeyRaw: rawPublicKey(publicKey) };
}

/**
 * A `KeyPair` around a private key this process already holds.
 *
 * The bridge from `loadOrCreateServerIdentity()`, which owns the key file and
 * returns a bare `KeyObject`, to the handshake, which needs the public half
 * alongside it. Kept here rather than in server-identity.ts so that module
 * stays about storing a key rather than about the protocol that uses it.
 */
export function keyPairFrom(privateKey: KeyObject): KeyPair {
  const publicKey = createPublicKey(privateKey);
  return { publicKey, privateKey, publicKeyRaw: rawPublicKey(publicKey) };
}

/**
 * Raw 32 bytes out of a KeyObject. JWK OKP `x` is base64url of exactly that.
 *
 * Accepts either half: `createPublicKey` derives the public key from a private
 * one but rejects a KeyObject that is already public, so the type is checked
 * rather than the call being made unconditionally.
 */
export function rawPublicKey(key: KeyObject): Buffer {
  const pub = key.type === "public" ? key : createPublicKey(key);
  const jwk = pub.export({ format: "jwk" });
  if (jwk.crv !== "X25519" || typeof jwk.x !== "string") {
    throw new NoiseError("Not an X25519 public key");
  }
  return Buffer.from(jwk.x, "base64url");
}

/**
 * A KeyObject from raw bytes, or a `NoiseError`.
 *
 * This is a trust boundary: the bytes are the QR's `spk` on the client side and
 * an attacker-supplied handshake message on the server side. A wrong length is
 * rejected here rather than being padded, truncated, or handed to a DH that
 * would fail somewhere less legible.
 */
export function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== DHLEN) {
    throw new NoiseError(`X25519 public key must be ${DHLEN} bytes, got ${raw.length}`);
  }
  try {
    return createPublicKey({
      key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
      format: "jwk",
    });
  } catch {
    // The input is dropped rather than interpolated: on the responder side it
    // is attacker-controlled, and echoing it into a log or an error is how a
    // parser becomes a reflection surface.
    throw new NoiseError("Invalid X25519 public key");
  }
}

/**
 * A keypair from a raw 32-byte private scalar.
 *
 * Exists for the committed test vectors: a vector is only a contract if the
 * keys are fixed, and there is no other way to hand Node a chosen X25519
 * private key. Not used by any production path — every real keypair comes from
 * `generateKeyPair()` or the identity key file.
 *
 * Goes through PKCS#8 DER rather than JWK because a JWK OKP private key must
 * carry a matching `x`, and the point here is to supply only `d`. The prefix is
 * the fixed X25519 PrivateKeyInfo header (RFC 8410): SEQUENCE, version 0,
 * AlgorithmIdentifier 1.3.101.110, then an OCTET STRING wrapping the 32-byte
 * scalar.
 */
export function keyPairFromRawPrivate(raw: Buffer): KeyPair {
  if (raw.length !== DHLEN) {
    throw new NoiseError(`X25519 private key must be ${DHLEN} bytes, got ${raw.length}`);
  }
  const der = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), raw]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  return { publicKey, privateKey, publicKeyRaw: rawPublicKey(publicKey) };
}

/**
 * The pair token as a 32-byte PSK.
 *
 * The token is `pt_<32 hex chars>` — 35 bytes of ASCII, and the spec requires
 * the PSK to be exactly 32. Hashing with a domain-separating label is the
 * standard way to fit it, and the label means this value can never collide with
 * some other use of the same token elsewhere in the system.
 *
 * Both implementations must compute this identically or the handshake fails
 * with no diagnostic beyond "decryption failed", which is why it is pinned by a
 * test vector rather than left as an obvious detail.
 */
export function pskFromPairToken(token: string): Buffer {
  return createHash("sha256")
    .update("threadbase-e2ee/1 psk", "utf-8")
    .update(token, "utf-8")
    .digest();
}

// ─── CipherState (spec §5.1) ────────────────────────────────────────

/**
 * ChaChaPoly nonce, per spec §12.3: 4 zero bytes then the 8-byte
 * **little-endian** encoding of n.
 *
 * Deliberately NOT the record layer's nonce, which is `direction(4) ||
 * counter(8)` big-endian (design.md §3.3). Two layers, two encodings, both
 * correct for their own specification — do not unify them.
 */
function chachaNonce(n: bigint): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64LE(n, 4);
  return nonce;
}

/**
 * Noise's `CipherState` (spec §5.1).
 *
 * Exported for two reasons, neither of them scaffolding. Phase 3's record layer
 * has to build a transport cipher from the buffers `split()` returns, so this is
 * the type it will construct. And the §5.1 rule that a failed decryption must
 * not advance `n` is unobservable through the handshake API — every AEAD
 * operation there runs at `n = 0`, because each is preceded by a `MixKey` that
 * calls `initializeKey`. Without a way to reach a cipher state directly, that
 * rule is protected by nothing: a "simplification" that advances before
 * verifying passes every other test in the suite.
 */
export class CipherState {
  /**
   * `#private`, not `private`: TypeScript's `private` is a compile-time
   * annotation over an ordinary own property, which `showHidden` prints and
   * `getOwnPropertyDescriptors` returns. A `#` field is not a property at all.
   */
  #k: Buffer | null = null;
  private n = 0n;

  constructor() {
    redactKeyMaterial(this, () => `CipherState { n: ${this.n}, k: <#private> }`);
  }

  initializeKey(key: Buffer | null): void {
    this.#k = key;
    this.n = 0n;
  }

  hasKey(): boolean {
    return this.#k !== null;
  }

  encryptWithAd(ad: Buffer, plaintext: Buffer): Buffer {
    if (!this.#k) return plaintext;
    const cipher = createCipheriv("chacha20-poly1305", this.#k, chachaNonce(this.n), {
      authTagLength: TAGLEN,
    });
    cipher.setAAD(ad, { plaintextLength: plaintext.length });
    const out = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    this.n += 1n;
    return out;
  }

  decryptWithAd(ad: Buffer, ciphertext: Buffer): Buffer {
    if (!this.#k) return ciphertext;
    if (ciphertext.length < TAGLEN) throw new NoiseError("Ciphertext shorter than its tag");
    const body = ciphertext.subarray(0, ciphertext.length - TAGLEN);
    const tag = ciphertext.subarray(ciphertext.length - TAGLEN);
    const decipher = createDecipheriv("chacha20-poly1305", this.#k, chachaNonce(this.n), {
      authTagLength: TAGLEN,
    });
    decipher.setAAD(ad, { plaintextLength: body.length });
    decipher.setAuthTag(tag);
    let out: Buffer;
    try {
      out = Buffer.concat([decipher.update(body), decipher.final()]);
    } catch {
      // The nonce is deliberately NOT advanced on failure (spec §5.1). A
      // handshake that fails is over; advancing would only make a retry fail
      // differently and hide the cause.
      throw new NoiseError("Decryption failed");
    }
    this.n += 1n;
    return out;
  }
}

// ─── SymmetricState (spec §5.2) ─────────────────────────────────────

class SymmetricState {
  /**
   * The LIVE chaining key. Both traffic keys are `HKDF(ck, "")`, so rendering
   * it hands over the whole session rather than a fragment — it printed at
   * `util.inspect`'s default depth before this became a `#` field.
   */
  #ck: Buffer;
  #h: Buffer;
  readonly #cipher = new CipherState();

  constructor(protocolName: string) {
    const name = Buffer.from(protocolName, "utf-8");
    // Spec §5.2: pad to HASHLEN if it fits, otherwise hash it. Our name is 36
    // bytes, so this is always the hash branch — written in full anyway, since
    // the alternative is a constant nobody can check against the spec.
    this.#h =
      name.length <= HASHLEN
        ? Buffer.concat([name, Buffer.alloc(HASHLEN - name.length)])
        : createHash("sha256").update(name).digest();
    this.#ck = Buffer.from(this.#h);
    this.#cipher.initializeKey(null);
    // `ck` is the LIVE chaining key, and both traffic keys are `HKDF(ck, "")` —
    // so rendering it hands over the whole session, not a fragment of it. It
    // printed at `util.inspect`'s DEFAULT depth, with no `showHidden` needed,
    // because this object was the one place the §13 rule had not reached.
    redactKeyMaterial(this, () => "SymmetricState { ck, h, cipher: <#private> }");
  }

  /**
   * Noise's HKDF (spec §4.3) is RFC 5869 with `salt = chaining_key`,
   * `ikm = input_key_material` and an EMPTY info, so Node's `hkdfSync` is
   * exactly it rather than approximately it. Using the platform's HKDF removes
   * the HMAC chain that would otherwise be the easiest thing here to get
   * subtly wrong.
   */
  private hkdf(ikm: Buffer, outputs: 2 | 3): Buffer[] {
    const raw = Buffer.from(hkdfSync("sha256", ikm, this.#ck, Buffer.alloc(0), HASHLEN * outputs));
    const out: Buffer[] = [];
    for (let i = 0; i < outputs; i++) out.push(raw.subarray(i * HASHLEN, (i + 1) * HASHLEN));
    return out;
  }

  mixKey(ikm: Buffer): void {
    const [ck, tempK] = this.hkdf(ikm, 2);
    this.#ck = ck;
    this.#cipher.initializeKey(tempK);
  }

  mixHash(data: Buffer): void {
    this.#h = createHash("sha256").update(this.#h).update(data).digest();
  }

  /** Spec §5.2. Used only by the `psk` token. */
  mixKeyAndHash(ikm: Buffer): void {
    const [ck, tempH, tempK] = this.hkdf(ikm, 3);
    this.#ck = ck;
    this.mixHash(tempH);
    this.#cipher.initializeKey(tempK);
  }

  encryptAndHash(plaintext: Buffer): Buffer {
    const ciphertext = this.#cipher.encryptWithAd(this.#h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  decryptAndHash(ciphertext: Buffer): Buffer {
    const plaintext = this.#cipher.decryptWithAd(this.#h, ciphertext);
    // Hashes the CIPHERTEXT, not the plaintext, and only after a successful
    // decrypt — so both sides' transcripts commit to the same bytes.
    this.mixHash(ciphertext);
    return plaintext;
  }

  /** The transcript hash. Both sides must arrive at the same value. */
  handshakeHash(): Buffer {
    return Buffer.from(this.#h);
  }

  /** Spec §5.2 `Split()`: the two directional transport keys. */
  split(): { k1: Buffer; k2: Buffer } {
    const [k1, k2] = this.hkdf(Buffer.alloc(0), 2);
    return { k1: Buffer.from(k1), k2: Buffer.from(k2) };
  }
}

// ─── The handshake ──────────────────────────────────────────────────

/**
 * The transport keys a completed handshake yields.
 *
 * **A class with `#private` fields, not an object literal**, because this is
 * the value that TRAVELS — out of `respond()`, through the route, into
 * `createRecordState` — and so it is the one most likely to end up inside an
 * error, a log line or a test diff. As a literal its two traffic keys were
 * ordinary properties: `defineProperty(enumerable: false)` hid them from
 * default `inspect` and `{ showHidden: true }` printed them anyway; the custom
 * inspect handler hid them from that and `{ customInspect: false }` printed
 * them anyway. A `#` field is not a property, so there is no mode to find.
 *
 * The getters are on the prototype, which `inspect` does not walk and
 * `getOwnPropertyDescriptors` does not report, so `keys.clientToServer` reads
 * exactly as it did while rendering nothing.
 */
export interface TrafficKeys {
  /** Initiator → responder. An OpenSSL key handle, never bytes. */
  readonly clientToServer: KeyObject;
  /** Responder → initiator. */
  readonly serverToClient: KeyObject;
  /** The transcript hash. Public, and an unpooled copy. */
  readonly handshakeHash: Buffer;
}

/**
 * The transport keys a completed handshake yields.
 *
 * **The keys are `KeyObject`s and there is no byte getter at all.** Hiding was
 * tried four ways and defeated four times — non-enumerable by `showHidden`, the
 * inspect handler by `customInspect: false`, `#private` fields by
 * `{ getters: true }` reading through the accessors, and finally `#private`
 * with no getter by the ALLOCATION POOL: Node pool-allocates small Buffers, a
 * Buffer's `.buffer` exposes the shared 8 KiB block, and a public Buffer on the
 * same object hands out a window onto the pool the private key was allocated
 * in. Hiding a Buffer cannot work, so no traffic-key bytes exist as a JS Buffer
 * after the handshake: they are imported into OpenSSL and the copies wiped.
 *
 * `consume()` is the only way out and it works once, so ownership of the keys
 * is a fact about the object rather than a convention.
 */
export class HandshakeKeys {
  #clientToServer: KeyObject | null;
  #serverToClient: KeyObject | null;
  readonly #handshakeHash: Buffer;

  constructor(handshakeHash: Buffer, clientToServer: Buffer, serverToClient: Buffer) {
    this.#handshakeHash = unpooled(handshakeHash);
    this.#clientToServer = importSecret(clientToServer);
    this.#serverToClient = importSecret(serverToClient);
    // These are `split()`'s outputs and this object owns them: wiped now, so the
    // window in which a traffic key exists as JS-visible bytes ends here.
    clientToServer.fill(0);
    serverToClient.fill(0);
    redactKeyMaterial(this, () => "HandshakeKeys { traffic keys: <KeyObject, off-heap> }");
  }

  /**
   * Hand the keys to the record layer. Once.
   *
   * NOT the transcript hash's guard — that is public — but the keys': a second
   * caller getting the same handles would mean two record layers believing they
   * own one counter space, which is the shape every nonce rule here exists to
   * prevent.
   */
  consume(): TrafficKeys {
    const clientToServer = this.#clientToServer;
    const serverToClient = this.#serverToClient;
    if (!clientToServer || !serverToClient) {
      throw new NoiseError("These handshake keys have already been consumed");
    }
    this.#clientToServer = null;
    this.#serverToClient = null;
    return { clientToServer, serverToClient, handshakeHash: unpooled(this.#handshakeHash) };
  }
}

function dh(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  return diffieHellman({ privateKey, publicKey });
}

/**
 * Message 1, from the phone.
 *
 * Exported from the *server* module although the server never sends one. It is
 * the only way to drive the responder in a test, and it generates the committed
 * vectors the tb-mobile implementation is checked against — a second, drifting
 * initiator written inside a test file is the precise failure two independent
 * implementations invite.
 */
export function writeMessage1(args: {
  staticKeyPair: KeyPair;
  responderStaticPub: Buffer;
  /** Required by `IKpsk1`, forbidden by `IK`. */
  psk?: Buffer;
  /** Defaults to the stronger `IKpsk1`. `/api/e2ee/open` passes `"IK"` (§11). */
  pattern?: NoisePattern;
  payload: Buffer;
  /** REQUIRED: `PAIR_PROLOGUE` or `OPEN_PROLOGUE`. Never defaulted (§11). */
  prologue: Buffer;
  /** Test seam only. Production always generates a fresh ephemeral. */
  ephemeral?: KeyPair;
}): { message: Buffer; state: HandshakeInitiatorState } {
  // `Object.hasOwn`, not `??`: `??` walks the prototype chain, so
  // `Object.prototype.pattern = "IK"` silently downgrades every psk-less call
  // site and breaks pairing. "The default is the stronger pattern" has to be
  // enforced, not commented.
  const pattern = Object.hasOwn(args, "pattern") ? (args.pattern as NoisePattern) : "IKpsk1";
  const state = new SymmetricState(protocolNameFor(pattern, args.psk));
  // REQUIRED, never defaulted. `args.prologue ??` is a prototype-chain read, so
  // `Object.prototype.prologue = OPEN_PROLOGUE` made the PAIRING handshake
  // accept an `/open` message — §11's domain separation collapsing through a
  // language default nobody wrote.
  // `own`, not `args.prologue`: making the parameter required is not enough,
  // because reading it directly is ITSELF the prototype-chain read. With
  // `Object.prototype.prologue` set, a call that passes none still found one.
  const prologue = own(args, "prologue");
  assertPrologue(prologue);
  state.mixHash(prologue);

  const rs = publicKeyFromRaw(args.responderStaticPub);
  // Pre-message `<- s`: the responder's static key is known in advance, from
  // the QR. This is what makes the QR an out-of-band authentication channel.
  state.mixHash(args.responderStaticPub);

  // Read off the ARGUMENT: a polluted `Object.prototype.ephemeral` pins every
  // handshake to one attacker-chosen `e`, which by §8's own rule is
  // definitionally a replay.
  const e = own(args, "ephemeral") ?? generateKeyPair();

  // `e`. In a PSK handshake the token also calls MixKey (spec §9.2), so the
  // ephemeral contributes to the chaining key before any DH — without it the
  // first message's payload would be protected by the PSK alone.
  state.mixHash(e.publicKeyRaw);
  state.mixKey(e.publicKeyRaw);

  // `es` — DH(initiator ephemeral, responder static).
  state.mixKey(dh(e.privateKey, rs));

  // `s` — the initiator's static key, transmitted ENCRYPTED. That is `IK`'s
  // identity-hiding property and the reason the pattern was chosen over `XX`.
  const encryptedStatic = state.encryptAndHash(args.staticKeyPair.publicKeyRaw);

  // `ss` — DH(initiator static, responder static).
  state.mixKey(dh(args.staticKeyPair.privateKey, rs));

  // `psk` — the pair token. Placed last in message 1 by the `psk1` modifier.
  // The `IK` pattern has no token here at all (§11), and `protocolNameFor` has
  // already refused the two incoherent combinations.
  if (pattern === "IKpsk1") state.mixKeyAndHash(args.psk as Buffer);

  const encryptedPayload = state.encryptAndHash(args.payload);

  const initiator: HandshakeInitiatorState = {
    symmetric: state,
    ephemeral: e,
    staticKeyPair: args.staticKeyPair,
  };
  // Holds the symmetric state and both keypairs. Redacted for the same reason
  // and through the same helper (§13).
  // Its `symmetric` is opaque by construction now, and the keypairs are Node
  // `KeyObject`s, which never render their bytes. The summary is for reading.
  redactKeyMaterial(initiator, () => "HandshakeInitiatorState { keys: <#private> }");

  return {
    message: Buffer.concat([e.publicKeyRaw, encryptedStatic, encryptedPayload]),
    state: initiator,
  };
}

export interface HandshakeInitiatorState {
  symmetric: SymmetricState;
  ephemeral: KeyPair;
  staticKeyPair: KeyPair;
}

/** Message 2, read by the phone. Completes the handshake. */
export function readMessage2(
  state: HandshakeInitiatorState,
  message: Buffer,
): { payload: Buffer; keys: HandshakeKeys } {
  assertMessageSize(message, NOISE_MESSAGE_2_OVERHEAD);
  const re = publicKeyFromRaw(message.subarray(0, DHLEN));

  state.symmetric.mixHash(message.subarray(0, DHLEN));
  state.symmetric.mixKey(message.subarray(0, DHLEN));
  state.symmetric.mixKey(dh(state.ephemeral.privateKey, re)); // ee
  state.symmetric.mixKey(dh(state.staticKeyPair.privateKey, re)); // se

  const payload = state.symmetric.decryptAndHash(message.subarray(DHLEN));
  return { payload, keys: finish(state.symmetric) };
}

export interface ResponderResult {
  /** The initiator's static public key, authenticated by the handshake. */
  initiatorStaticPub: Buffer;
  payload: Buffer;
  message2: Buffer;
  keys: HandshakeKeys;
}

/**
 * Half-completed responder state, between reading message 1 and writing 2.
 *
 * Deliberately only ever a local: it is handed straight back into
 * `writeMessage2` within the same synchronous stretch of one request, never
 * stored, never keyed by anything a caller supplies. A responder state that
 * outlived a request would be a thing to allocate and expire on a public
 * endpoint, which is what the single-call shape originally avoided.
 */
export interface HandshakeResponderState {
  symmetric: SymmetricState;
  /** The initiator's static public key, authenticated by message 1. */
  initiatorStaticPub: Buffer;
  /** Message 1's decrypted payload. */
  payload: Buffer;
  initiatorEphemeral: KeyObject;
  initiatorStatic: KeyObject;
  staticKeyPair: KeyPair;
}

/**
 * Read message 1. Authenticates the initiator and recovers its static key.
 *
 * Split from `writeMessage2` because the server DOES now have something to do
 * between them: message 2's payload carries the `deviceId`, and the device row
 * cannot be written until the pair token has been spent, which cannot happen
 * until this half has succeeded. The original single-call shape assumed nothing
 * sat in the middle; the pairing handler is the caller that proved otherwise.
 *
 * SYNCHRONOUS on purpose, and it must stay that way: the caller runs this
 * between validating the pair token and consuming it, and `PairTokenStore` has
 * no lock. An `await` in that gap would let two concurrent requests with the
 * same token both pass validation.
 */
export function readMessage1(args: {
  staticKeyPair: KeyPair;
  /** Required by `IKpsk1`, forbidden by `IK`. */
  psk?: Buffer;
  /** Defaults to the stronger `IKpsk1`. `/api/e2ee/open` passes `"IK"` (§11). */
  pattern?: NoisePattern;
  message1: Buffer;
  /** REQUIRED: `PAIR_PROLOGUE` or `OPEN_PROLOGUE`. Never defaulted (§11). */
  prologue: Buffer;
}): HandshakeResponderState {
  assertMessageSize(args.message1, NOISE_MESSAGE_1_OVERHEAD);

  // `Object.hasOwn`, not `??`: `??` walks the prototype chain, so
  // `Object.prototype.pattern = "IK"` silently downgrades every psk-less call
  // site and breaks pairing. "The default is the stronger pattern" has to be
  // enforced, not commented.
  const pattern = Object.hasOwn(args, "pattern") ? (args.pattern as NoisePattern) : "IKpsk1";
  const state = new SymmetricState(protocolNameFor(pattern, args.psk));
  // REQUIRED, never defaulted. `args.prologue ??` is a prototype-chain read, so
  // `Object.prototype.prologue = OPEN_PROLOGUE` made the PAIRING handshake
  // accept an `/open` message — §11's domain separation collapsing through a
  // language default nobody wrote.
  // `own`, not `args.prologue`: making the parameter required is not enough,
  // because reading it directly is ITSELF the prototype-chain read. With
  // `Object.prototype.prologue` set, a call that passes none still found one.
  const prologue = own(args, "prologue");
  assertPrologue(prologue);
  state.mixHash(prologue);
  state.mixHash(args.staticKeyPair.publicKeyRaw);

  // `e`
  const reRaw = args.message1.subarray(0, DHLEN);
  const re = publicKeyFromRaw(reRaw);
  state.mixHash(reRaw);
  state.mixKey(reRaw);

  // `es` — from the responder's side, its static against the initiator's ephemeral.
  state.mixKey(dh(args.staticKeyPair.privateKey, re));

  // `s` — decrypting this is the first point an attacker without the right
  // static key fails, and it happens before the payload is touched.
  const encryptedStatic = args.message1.subarray(DHLEN, DHLEN + DHLEN + TAGLEN);
  const initiatorStaticPub = state.decryptAndHash(encryptedStatic);
  const rs = publicKeyFromRaw(initiatorStaticPub);

  // `ss`
  state.mixKey(dh(args.staticKeyPair.privateKey, rs));

  // `psk` — the `IK` pattern has no token here (§11).
  if (pattern === "IKpsk1") state.mixKeyAndHash(args.psk as Buffer);

  const payload = state.decryptAndHash(args.message1.subarray(DHLEN + DHLEN + TAGLEN));

  const responder: HandshakeResponderState = {
    symmetric: state,
    initiatorStaticPub,
    payload,
    initiatorEphemeral: re,
    initiatorStatic: rs,
    staticKeyPair: args.staticKeyPair,
  };
  redactKeyMaterial(responder, () => "HandshakeResponderState { keys: <#private> }");
  return responder;
}

/** Write message 2 and derive the transport keys. Completes the handshake. */
export function writeMessage2(
  state: HandshakeResponderState,
  responsePayload: Buffer,
  /** Test seam only. Production always generates a fresh ephemeral. */
  ephemeral?: KeyPair,
): { message2: Buffer; keys: HandshakeKeys } {
  const e = ephemeral ?? generateKeyPair();
  state.symmetric.mixHash(e.publicKeyRaw);
  state.symmetric.mixKey(e.publicKeyRaw);
  state.symmetric.mixKey(dh(e.privateKey, state.initiatorEphemeral)); // ee
  state.symmetric.mixKey(dh(e.privateKey, state.initiatorStatic)); // se

  const encryptedPayload = state.symmetric.encryptAndHash(responsePayload);
  return {
    message2: Buffer.concat([e.publicKeyRaw, encryptedPayload]),
    keys: finish(state.symmetric),
  };
}

/**
 * Both halves in one call.
 *
 * Kept because most callers — every test, and any future responder with nothing
 * to do in the middle — want the whole handshake, and because the two halves
 * being separable should not force every one of them to sequence it by hand.
 */
export function respond(args: {
  staticKeyPair: KeyPair;
  /** Required by `IKpsk1`, forbidden by `IK`. */
  psk?: Buffer;
  /** Defaults to the stronger `IKpsk1`. `/api/e2ee/open` passes `"IK"` (§11). */
  pattern?: NoisePattern;
  message1: Buffer;
  /** Built from the authenticated message-1 payload; sealed into message 2. */
  buildPayload: (initiatorStaticPub: Buffer, payload: Buffer) => Buffer;
  /** REQUIRED: `PAIR_PROLOGUE` or `OPEN_PROLOGUE`. Never defaulted (§11). */
  prologue: Buffer;
  /** Test seam only. */
  ephemeral?: KeyPair;
}): ResponderResult {
  const state = readMessage1(args);
  const { initiatorStaticPub, payload } = state;
  const { message2, keys } = writeMessage2(
    state,
    args.buildPayload(initiatorStaticPub, payload),
    // `own`, like the initiator half at `writeMessage1`. Reading `args.ephemeral`
    // bare is a prototype-chain read, and a polluted `Object.prototype.ephemeral`
    // pins the RESPONDER's `e` across every `respond()` — two calls producing
    // byte-identical messages, which by §8's own rule is definitionally a replay.
    own(args, "ephemeral"),
  );

  return { initiatorStaticPub, payload, message2, keys };
}

function finish(state: SymmetricState): HandshakeKeys {
  const { k1, k2 } = state.split();
  // Spec §5.2: the first key is always initiator→responder, whichever side
  // called Split(). Naming them by direction here means no call site has to
  // remember which end it is.
  return new HandshakeKeys(state.handshakeHash(), k1, k2);
}

/**
 * Size check before anything is parsed or allocated.
 *
 * D-9's rule reaching forward from the unseal middleware to here: this runs on
 * a public, pre-authentication endpoint, so a message is bounded before it is
 * read and nothing is ever allocated in proportion to an attacker-supplied
 * length.
 */
function assertMessageSize(message: Buffer, minimum: number): void {
  if (message.length < minimum) {
    throw new NoiseError(`Handshake message too short: ${message.length} < ${minimum}`);
  }
  if (message.length > NOISE_MAX_MESSAGE_BYTES) {
    throw new NoiseError(`Handshake message too large: ${message.length}`);
  }
}
