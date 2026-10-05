import { createHash } from "crypto";
import {
  CipherState,
  generateKeyPair,
  keyPairFromRawPrivate,
  NOISE_MAX_MESSAGE_BYTES,
  NOISE_PROTOCOL_NAME,
  NoiseError,
  OPEN_PROLOGUE,
  PAIR_PROLOGUE,
  pskFromPairToken,
  readMessage1,
  readMessage2,
  respond,
  writeMessage1,
  writeMessage2,
} from "../src/noise/noise";
import vectors from "./fixtures/noise-ikpsk1-vectors.json";

/**
 * Noise_IKpsk1_25519_ChaChaPoly_SHA256 (#590, Phase 2).
 *
 * A test that asserts "it encrypted something" passes on a broken
 * implementation, so none of these do that. What is asserted is the three
 * properties the handshake exists for:
 *
 *   1. A handshake against a static key OTHER than the QR's fails — this is
 *      server authentication, and it is the whole reason `spk` is in the QR.
 *   2. A wrong or absent PSK fails — the pair token genuinely binds the
 *      handshake to *this* QR rather than being mixed in and ignored.
 *   3. A tampered ciphertext is rejected, anywhere in the message.
 *
 * Plus the interop contract: fixed keys produce exactly the committed bytes, so
 * tb-mobile's independent implementation can be checked against the same file.
 *
 * WHEN ADDING A NEGATIVE TEST HERE, the obvious shape is the broken one.
 * An assertion placed inside exception-handling control flow cannot distinguish
 * "failed correctly" from "never ran" — the catch block executes only on
 * failure, so it is silent about the case where nothing failed at all. The
 * "fails before the initiator's payload is ever decrypted" test below was
 * written that way first and would have passed against an implementation with
 * no server authentication whatsoever. Every negative test here therefore pairs
 * with a positive control that proves the observation fires when it should.
 */

const b64 = (s: string) => Buffer.from(s, "base64");

const serverStatic = keyPairFromRawPrivate(b64(vectors.keys.serverStaticPrivate));
const clientStatic = keyPairFromRawPrivate(b64(vectors.keys.clientStaticPrivate));
const clientEphemeral = keyPairFromRawPrivate(b64(vectors.keys.clientEphemeralPrivate));
const serverEphemeral = keyPairFromRawPrivate(b64(vectors.keys.serverEphemeralPrivate));

const PAYLOAD_1 = Buffer.from(vectors.payload1Utf8, "utf-8");
const PAYLOAD_2 = Buffer.from(vectors.payload2Utf8, "utf-8");
const PSK = pskFromPairToken(vectors.pairToken);

/** One complete handshake with fresh keys, as production runs it. */
function handshake(
  over: { responderStaticPub?: Buffer; clientPsk?: Buffer; serverPsk?: Buffer } = {},
) {
  const server = generateKeyPair();
  const client = generateKeyPair();
  const psk = pskFromPairToken("pt_ffeeddccbbaa99887766554433221100");

  const initiator = writeMessage1({
    prologue: PAIR_PROLOGUE,
    staticKeyPair: client,
    responderStaticPub: over.responderStaticPub ?? server.publicKeyRaw,
    psk: over.clientPsk ?? psk,
    payload: PAYLOAD_1,
  });
  const responder = () =>
    respond({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: server,
      psk: over.serverPsk ?? psk,
      message1: initiator.message,
      buildPayload: () => PAYLOAD_2,
    });
  return { server, client, psk, initiator, responder };
}

describe("a complete IKpsk1 handshake", () => {
  it("leaves both sides holding the same transcript and the same traffic keys", () => {
    const { initiator, responder } = handshake();
    const server = responder();
    const client = readMessage2(initiator.state, server.message2);

    // The transcript hash is what `ctxId` is derived from, so a disagreement
    // here would surface later as an unexplained context mismatch.
    // `consume()` is the only way to the keys, and it yields KeyObjects; the
    // test reaches for bytes through `export()`, which no `src/` caller does.
    const clientKeys = client.keys.consume();
    const serverKeys = server.keys.consume();
    expect(clientKeys.handshakeHash.equals(serverKeys.handshakeHash)).toBe(true);
    expect(clientKeys.clientToServer.export().equals(serverKeys.clientToServer.export())).toBe(
      true,
    );
    expect(clientKeys.serverToClient.export().equals(serverKeys.serverToClient.export())).toBe(
      true,
    );

    // Separate keys per direction, so a record can never be reflected at its
    // sender (design.md §3.3).
    expect(clientKeys.clientToServer.export().equals(clientKeys.serverToClient.export())).toBe(
      false,
    );
  });

  it("authenticates the initiator's static key rather than trusting a claim", () => {
    const { client, initiator, responder } = handshake();
    const server = responder();
    // `IK` transmits the initiator's static key ENCRYPTED, and the responder
    // recovers it from the transcript. This is the value that becomes
    // devices.e2ee_static_pub, so it must be the key, not a field.
    expect(server.initiatorStaticPub.equals(client.publicKeyRaw)).toBe(true);
    expect(initiator.message.includes(client.publicKeyRaw)).toBe(false);
  });

  it("carries each side's payload to the other", () => {
    const { initiator, responder } = handshake();
    const server = responder();
    expect(server.payload.equals(PAYLOAD_1)).toBe(true);
    expect(readMessage2(initiator.state, server.message2).payload.equals(PAYLOAD_2)).toBe(true);
  });

  it("produces a different transcript every time", () => {
    // Fresh ephemerals, so two handshakes between the same two static keys
    // share no key material. This is where the forward secrecy in design.md
    // §4.3 comes from; without it a recovered static key would decrypt every
    // captured session.
    const a = handshake();
    const b = handshake();
    expect(
      a.responder().keys.consume().handshakeHash.equals(b.responder().keys.consume().handshakeHash),
    ).toBe(false);
  });
});

describe("server authentication", () => {
  /**
   * The property the QR exists for.
   *
   * A man in the middle can answer the exchange, but cannot prove possession of
   * the private half of the `spk` the phone scanned. The `es` and `ss` mixes
   * both involve that key, so its transcript diverges and the very first
   * decryption fails.
   */
  it("fails when the responder is not the key the QR carried", () => {
    const impostor = generateKeyPair();
    // The phone believes it is talking to `impostor`; the real responder holds
    // a different static key.
    const { responder } = handshake({ responderStaticPub: impostor.publicKeyRaw });
    expect(responder).toThrow(NoiseError);
  });

  /**
   * §9 of design.md asks for this specifically: the failure must happen before
   * any payload is decrypted. It does, because the `s` token is decrypted first
   * and the payload only after — a wrong static key never reaches the payload.
   */
  it("fails before the initiator's payload is ever decrypted", () => {
    // `buildPayload` receives the decrypted payload and runs immediately after
    // it decrypts, so whether it was called IS whether the payload was read.
    // Written as a spy rather than as an assertion inside a catch block: a
    // catch that only records "nothing happened" also records nothing when the
    // handshake succeeds, and would pass on an implementation with no server
    // authentication at all.
    const run = (believedResponderPub: Buffer | null, seen: Buffer[]) => {
      const server = generateKeyPair();
      const client = generateKeyPair();
      const psk = pskFromPairToken("pt_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
      const { message } = writeMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: client,
        responderStaticPub: believedResponderPub ?? server.publicKeyRaw,
        psk,
        payload: PAYLOAD_1,
      });
      return () =>
        respond({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: server,
          psk,
          message1: message,
          buildPayload: (_static, payload) => {
            seen.push(payload);
            return PAYLOAD_2;
          },
        });
    };

    // Positive control first, and it is the reason this test is worth
    // anything: against the right key the payload IS read, so the empty array
    // below means the handshake stopped rather than that the spy never fires.
    const honest: Buffer[] = [];
    run(null, honest)();
    expect(honest).toHaveLength(1);

    const impostor: Buffer[] = [];
    expect(run(generateKeyPair().publicKeyRaw, impostor)).toThrow(NoiseError);
    expect(impostor).toHaveLength(0);
  });
});

describe("the pair token actually binds the handshake", () => {
  /**
   * Without this the `psk` could be mixed in and ignored — the handshake would
   * still succeed, and "the client scanned THIS QR" would be a claim rather
   * than a proof.
   */
  it("fails when the two sides mix different pair tokens", () => {
    const { responder } = handshake({
      clientPsk: pskFromPairToken("pt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      serverPsk: pskFromPairToken("pt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    });
    expect(responder).toThrow(NoiseError);
  });

  it("fails on a single flipped bit in the token", () => {
    const { responder } = handshake({
      clientPsk: pskFromPairToken("pt_00000000000000000000000000000000"),
      serverPsk: pskFromPairToken("pt_00000000000000000000000000000001"),
    });
    expect(responder).toThrow(NoiseError);
  });

  it("derives the PSK from the token with a domain-separating label", () => {
    // Pinned because both implementations must agree byte for byte, and a
    // mismatch shows up only as "decryption failed" with no hint of the cause.
    const token = vectors.pairToken;
    const expected = createHash("sha256")
      .update("threadbase-e2ee/1 psk", "utf-8")
      .update(token, "utf-8")
      .digest();
    expect(pskFromPairToken(token).equals(expected)).toBe(true);
    // Not the bare token hash — the label is what stops this value colliding
    // with any other use of the same token.
    expect(pskFromPairToken(token).equals(createHash("sha256").update(token).digest())).toBe(false);
  });
});

describe("cipher state (spec §5.1)", () => {
  /**
   * A decryption that fails authentication must NOT advance `n`.
   *
   * Nothing else in this file can catch a regression here. The tampering tests
   * below build fresh state for every iteration on purpose — reusing one would
   * test a corrupted state rather than a corrupted message — so the
   * reuse-after-failure path is the one they never exercise. And the handshake
   * API cannot reach it either: every AEAD operation there runs at `n = 0`,
   * because each is preceded by a `MixKey` that calls `initializeKey`. Verified
   * by breaking it: moving the `this.n += 1n` in `decryptWithAd` above the
   * try/catch fails this test and leaves the other 17 in this file green.
   *
   * The property only becomes load-bearing in Phase 3, when a transport cipher
   * outlives a single frame and a rejected record must not cost a counter slot.
   * It is asserted now because that is when it is cheap.
   */
  it("does not advance the nonce when a frame fails to authenticate", () => {
    const key = createHash("sha256").update("§5.1 nonce-advance fixture").digest();
    const ad = Buffer.from("transcript-derived AAD");

    const sender = new CipherState();
    sender.initializeKey(key);
    const opener = new CipherState();
    opener.initializeKey(key);

    const frame = sender.encryptWithAd(ad, Buffer.from("first record"));

    const corrupted = Buffer.from(frame);
    corrupted[0] ^= 0x01;
    expect(() => opener.decryptWithAd(ad, corrupted)).toThrow(NoiseError);

    // The genuine frame was sealed at counter 0. If the rejected one had burned
    // that slot, this runs at counter 1 and fails — so this line, not the throw
    // above, is what asserts the rule.
    expect(opener.decryptWithAd(ad, frame).toString()).toBe("first record");
  });
});

describe("tampering", () => {
  /**
   * Every byte of message 1 is covered: the ephemeral is hashed into the
   * transcript, and the two ciphertexts each carry a Poly1305 tag over a
   * transcript-derived AAD.
   *
   * Stepping one byte at a time rather than picking three — a gap in the
   * coverage would be a region an intermediary can rewrite, and the point of
   * checking is not knowing in advance where that would be.
   */
  it("rejects a flip at any offset in message 1", () => {
    const { server, psk, initiator } = handshake();
    for (let i = 0; i < initiator.message.length; i++) {
      const tampered = Buffer.from(initiator.message);
      tampered[i] ^= 0x01;
      expect(() =>
        respond({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: server,
          psk,
          message1: tampered,
          buildPayload: () => PAYLOAD_2,
        }),
      ).toThrow(NoiseError);
    }
  });

  it("rejects a flip at any offset in message 2", () => {
    const server = handshake().responder();
    for (let i = 0; i < server.message2.length; i++) {
      const tampered = Buffer.from(server.message2);
      tampered[i] ^= 0x01;
      // A fresh initiator state per attempt: reading message 2 mutates the
      // symmetric state, so reusing one would test a corrupted state rather
      // than a corrupted message.
      const fresh = writeMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: clientStatic,
        responderStaticPub: serverStatic.publicKeyRaw,
        psk: PSK,
        payload: PAYLOAD_1,
        ephemeral: clientEphemeral,
      });
      respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: serverStatic,
        psk: PSK,
        message1: fresh.message,
        buildPayload: () => PAYLOAD_2,
        ephemeral: serverEphemeral,
      });
      expect(() => readMessage2(fresh.state, tampered)).toThrow(NoiseError);
    }
  });

  it("rejects a truncated message rather than reading past its end", () => {
    const { server, psk, initiator } = handshake();
    for (const length of [0, 1, 31, 32, 79]) {
      expect(() =>
        respond({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: server,
          psk,
          message1: initiator.message.subarray(0, length),
          buildPayload: () => PAYLOAD_2,
        }),
      ).toThrow(NoiseError);
    }
  });

  /**
   * D-9's rule, reaching forward from the unseal middleware: this runs on a
   * public pre-authentication endpoint, so the size is checked before anything
   * is parsed and nothing is allocated in proportion to an attacker's length.
   */
  it("refuses an oversized message before parsing it", () => {
    const { server, psk } = handshake();
    const huge = Buffer.alloc(NOISE_MAX_MESSAGE_BYTES + 1);
    expect(() =>
      respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        psk,
        message1: huge,
        buildPayload: () => PAYLOAD_2,
      }),
    ).toThrow(/too large/);
  });

  it("refuses a malformed public key without echoing it back", () => {
    const { server, psk, initiator } = handshake();
    const tampered = Buffer.from(initiator.message);
    tampered.fill(0, 0, 32); // an all-zero X25519 key: low order, no shared secret
    let message = "";
    try {
      respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        psk,
        message1: tampered,
        buildPayload: () => PAYLOAD_2,
      });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).not.toBe("");
    // The rejected bytes are attacker-controlled; an error that echoed them
    // would make the parser a reflection surface for anything downstream that
    // logs it.
    expect(message).not.toMatch(/[A-Za-z0-9+/]{20,}/);
  });
});

describe("the interop contract with tb-mobile", () => {
  /**
   * The one thing that catches a transcript divergence between two independent
   * implementations of the same specification.
   *
   * tb-mobile's `@stablelib` half checks the same file. If either side changes
   * a token order, a nonce encoding, a hash input, or the PSK derivation, these
   * bytes stop matching before anything ships — rather than the two sides
   * failing to pair in the field with nothing but "decryption failed" to go on.
   */
  it("reproduces the committed messages exactly from fixed keys", () => {
    const initiator = writeMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: clientStatic,
      responderStaticPub: serverStatic.publicKeyRaw,
      psk: PSK,
      payload: PAYLOAD_1,
      ephemeral: clientEphemeral,
    });
    expect(initiator.message.toString("base64")).toBe(vectors.message1);

    const server = respond({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: serverStatic,
      psk: PSK,
      message1: initiator.message,
      buildPayload: () => PAYLOAD_2,
      ephemeral: serverEphemeral,
    });
    expect(server.message2.toString("base64")).toBe(vectors.message2);
    const serverKeys = server.keys.consume();
    expect(serverKeys.handshakeHash.toString("base64")).toBe(vectors.handshakeHash);
    expect(serverKeys.clientToServer.export().toString("base64")).toBe(vectors.clientToServerKey);
    expect(serverKeys.serverToClient.export().toString("base64")).toBe(vectors.serverToClientKey);

    const client = readMessage2(initiator.state, server.message2);
    expect(client.keys.consume().handshakeHash.toString("base64")).toBe(vectors.handshakeHash);
  });

  it("pins the protocol name and the prologue, which the transcript commits to", () => {
    // Both are hashed into `h` before any token, so a change to either is a
    // silent, total incompatibility — the kind that presents as "decryption
    // failed" and nothing else.
    expect(NOISE_PROTOCOL_NAME).toBe(vectors.protocolName);
    expect(PAIR_PROLOGUE.toString("utf-8")).toBe(vectors.prologueUtf8);
    expect(PSK.toString("base64")).toBe(vectors.psk);
  });

  it("pins the public keys the private scalars derive to", () => {
    // Guards the PKCS#8 construction in keyPairFromRawPrivate: a wrong DER
    // prefix would produce a valid-looking but different key, and every other
    // vector assertion would fail together with no indication of the cause.
    expect(serverStatic.publicKeyRaw.toString("base64")).toBe(vectors.keys.serverStaticPublic);
    expect(clientStatic.publicKeyRaw.toString("base64")).toBe(vectors.keys.clientStaticPublic);
  });
});

/**
 * Which pattern a handshake runs is STATED, never inferred from whether a psk
 * happens to have been passed (NONCE-DESIGN §11).
 *
 * The inferred form was fail-open at a trust boundary: a pairing call site that
 * forgot its `psk` would not have failed, it would have silently run plain `IK`
 * and lost the pair-token binding that is the whole reason pairing uses
 * `IKpsk1` (spec §9.3, design.md §2.4). A forgotten argument must never be a
 * downgrade.
 */
describe("pattern selection is explicit", () => {
  const server = generateKeyPair();
  const client = generateKeyPair();
  const psk = pskFromPairToken("pt_00112233445566778899aabbccddeeff");
  const payload = Buffer.from("{}", "utf-8");

  it("refuses IKpsk1 without a psk, which is the downgrade that used to be silent", () => {
    // The DEFAULT pattern, reached by a call site that simply forgot the psk.
    expect(() =>
      writeMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: client,
        responderStaticPub: server.publicKeyRaw,
        payload,
      }),
    ).toThrow(/requires a 32-byte psk/);

    const { message } = writeMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: client,
      responderStaticPub: server.publicKeyRaw,
      psk,
      payload,
    });
    expect(() =>
      readMessage1({ prologue: PAIR_PROLOGUE, staticKeyPair: server, message1: message }),
    ).toThrow(/requires a 32-byte psk/);
  });

  it("refuses an EMPTY or short psk, which a presence check let through (round 4)", () => {
    // `Buffer.alloc(0)` is truthy, so `if (!psk)` completed a full `IKpsk1`
    // handshake over an empty psk: right protocol name, right token order,
    // `mixKeyAndHash` over zero bytes. The wire says `IKpsk1` and the binding
    // is a constant — exactly what §11 refused when it rejected a public
    // constant PSK, arrived at through a guard instead of a decision.
    for (const bad of [Buffer.alloc(0), Buffer.alloc(31, 0x11), Buffer.alloc(33, 0x11)]) {
      expect(() =>
        writeMessage1({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: client,
          responderStaticPub: server.publicKeyRaw,
          pattern: "IKpsk1",
          psk: bad,
          payload,
        }),
      ).toThrow(/requires a 32-byte psk/);
      expect(() =>
        readMessage1({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: server,
          pattern: "IKpsk1",
          psk: bad,
          message1: Buffer.alloc(200),
        }),
      ).toThrow(/requires a 32-byte psk/);
    }

    // The control: a real 32-byte psk still completes both halves.
    const good = writeMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: client,
      responderStaticPub: server.publicKeyRaw,
      pattern: "IKpsk1",
      psk,
      payload,
    });
    expect(() =>
      readMessage1({ prologue: PAIR_PROLOGUE, staticKeyPair: server, psk, message1: good.message }),
    ).not.toThrow();
  });

  it("reads the pattern default off the ARGUMENT, never the prototype chain (round 4)", () => {
    // `args.pattern ?? "IKpsk1"` walks the prototype chain, so a polluted
    // `Object.prototype.pattern` silently downgraded every psk-less call site
    // to plain `IK` — and broke pairing, which is the caller that depends on
    // the default being the stronger pattern.
    const polluted = Object.prototype as { pattern?: string };
    polluted.pattern = "IK";
    try {
      // A pairing call site passes a psk and no pattern: it must still be
      // IKpsk1, so the psk is accepted rather than refused as "IK takes none".
      expect(() =>
        writeMessage1({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: client,
          responderStaticPub: server.publicKeyRaw,
          psk,
          payload,
        }),
      ).not.toThrow();
    } finally {
      delete polluted.pattern;
    }
  });

  it("refuses IK WITH a psk, because that is the same confusion facing the other way", () => {
    expect(() =>
      writeMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: client,
        responderStaticPub: server.publicKeyRaw,
        pattern: "IK",
        psk,
        payload,
      }),
    ).toThrow(/takes no psk/);
    expect(() =>
      readMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        pattern: "IK",
        psk,
        message1: Buffer.alloc(200),
      }),
    ).toThrow(/takes no psk/);
  });

  it("refuses a pattern string it does not recognise, rather than defaulting (adversary F)", () => {
    // The selector used to end in `pattern === "IKpsk1" ? A : B`, so anything
    // that matched neither guard fell through to psk-less `IK` and silently
    // dropped the pair-token binding. TypeScript rules this out for callers in
    // this repository; the client track consumes the module as an artefact, and
    // these values arrive from config and wire fields, not only typed source.
    for (const bogus of ["IKPSK1", "ik", "IKpsk", "", "Noise_IK", "iKpSk1"]) {
      expect(() =>
        writeMessage1({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: client,
          responderStaticPub: server.publicKeyRaw,
          pattern: bogus as "IK",
          psk,
          payload,
        }),
      ).toThrow(/Unknown Noise pattern/);
      expect(() =>
        readMessage1({
          prologue: PAIR_PROLOGUE,
          staticKeyPair: server,
          pattern: bogus as "IK",
          psk,
          message1: Buffer.alloc(200),
        }),
      ).toThrow(/Unknown Noise pattern/);
    }
  });

  it("still completes both patterns when the pairing is coherent", () => {
    // The control: the guards refuse incoherent combinations and nothing else.
    const paired = writeMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: client,
      responderStaticPub: server.publicKeyRaw,
      pattern: "IKpsk1",
      psk,
      payload,
    });
    expect(
      respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        psk,
        message1: paired.message,
        buildPayload: () => payload,
      }).payload.toString(),
    ).toBe("{}");

    const open = writeMessage1({
      staticKeyPair: client,
      responderStaticPub: server.publicKeyRaw,
      pattern: "IK",
      payload,
      prologue: OPEN_PROLOGUE,
    });
    expect(
      respond({
        staticKeyPair: server,
        pattern: "IK",
        message1: open.message,
        prologue: OPEN_PROLOGUE,
        buildPayload: () => payload,
      }).payload.toString(),
    ).toBe("{}");
  });
});

/**
 * Key hygiene on the handshake states (adversary E-4).
 *
 * `SymmetricState` holds `ck`, the live chaining key — and BOTH traffic keys
 * are `HKDF(ck, "")`, so rendering it hands over the whole session rather than a
 * fragment. It printed at `util.inspect`'s DEFAULT depth, no `showHidden`
 * needed, because these four objects were the ones §13's "every object holding
 * key material installs a handler" had not reached.
 *
 * The assertion is needle-free on purpose: it checks that NO buffer renders at
 * all, so no key bytes appear in the test, in its failure output, or in a log
 * that captures either.
 */
describe("the responder reads its ephemeral off the argument too (round 6)", () => {
  it("mints a fresh e per respond(), even under a polluted prototype", () => {
    // `writeMessage1` used `own` and `respond` did not, so a polluted
    // `Object.prototype.ephemeral` pinned the RESPONDER's `e` across every
    // call: two `respond()`s producing byte-identical message 2s, which by §8's
    // own rule is definitionally a replay.
    const server = generateKeyPair();
    const client = generateKeyPair();
    const pinned = generateKeyPair();
    const psk = pskFromPairToken("pt_00112233445566778899aabbccddeeff");
    const msg1 = () =>
      writeMessage1({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: client,
        responderStaticPub: server.publicKeyRaw,
        psk,
        payload: Buffer.from("{}", "utf-8"),
      }).message;

    const proto = Object.prototype as Record<string, unknown>;
    proto.ephemeral = pinned;
    try {
      const a = respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        psk,
        message1: msg1(),
        buildPayload: () => Buffer.from("{}", "utf-8"),
      }).message2;
      const b = respond({
        prologue: PAIR_PROLOGUE,
        staticKeyPair: server,
        psk,
        message1: msg1(),
        buildPayload: () => Buffer.from("{}", "utf-8"),
      }).message2;

      // Different ephemerals, so different messages — and neither is the
      // attacker's.
      expect(a.subarray(0, 32).equals(b.subarray(0, 32))).toBe(false);
      expect(a.subarray(0, 32).equals(pinned.publicKeyRaw)).toBe(false);
    } finally {
      delete proto.ephemeral;
    }
  });
});

describe("handshake states hold their key material as #private", () => {
  /**
   * The mechanism, asserted where the handshake lives. The exhaustive
   * rendering-mode matrix — `showHidden`, `customInspect: false`, both
   * together, descriptors, spread, `structuredClone` — is in
   * `e2ee-record.test.ts`, which owns the detector; this asserts the property
   * the mechanism rests on: these are not properties at all.
   */
  it("keeps ck, h and k off the object entirely", () => {
    const server = generateKeyPair();
    const client = generateKeyPair();
    const psk = pskFromPairToken("pt_00112233445566778899aabbccddeeff");
    const payload = Buffer.from("{}", "utf-8");

    const cipher = new CipherState();
    cipher.initializeKey(Buffer.alloc(32, 0x11));
    expect(Object.getOwnPropertyNames(cipher)).not.toContain("k");

    const initiator = writeMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: client,
      responderStaticPub: server.publicKeyRaw,
      psk,
      payload,
    });
    const responder = readMessage1({
      prologue: PAIR_PROLOGUE,
      staticKeyPair: server,
      psk,
      message1: initiator.message,
    });

    for (const symmetric of [initiator.state.symmetric, responder.symmetric]) {
      const own = Object.getOwnPropertyNames(symmetric as object);
      expect(own).not.toContain("ck");
      expect(own).not.toContain("h");
      expect(own).not.toContain("cipher");
    }

    const finished = writeMessage2(responder, payload);
    const own = Object.getOwnPropertyNames(finished.keys);
    expect(own).not.toContain("clientToServer");
    expect(own).not.toContain("serverToClient");
    // A `#private` is invisible to a descriptor walk, which is what a generic
    // serializer does.
    expect(Object.keys(Object.getOwnPropertyDescriptors(finished.keys))).toHaveLength(0);

    // Reading still works, and the handshake still completes.
    expect(finished.keys.consume().clientToServer.export()).toHaveLength(32);
    expect(readMessage2(initiator.state, finished.message2).payload.toString()).toBe("{}");
  });
});
