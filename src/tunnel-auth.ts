import { createCipheriv, createDecipheriv, createHash, type KeyObject } from "crypto";
import {
  type HandshakeInitiatorState,
  type KeyPair,
  NoiseError,
  readMessage1,
  readMessage2,
  writeMessage1,
  writeMessage2,
} from "./noise/noise";

// How a streamer proves it owns a route.
//
// The route id is a hash of the streamer's X25519 identity key, and the tunnel
// opens with a Noise IK handshake in which that key is the initiator's static
// key. So a route can only be attached by whoever holds the private key it is
// derived from: there is nothing to register and nothing to claim.
//
// Message 1 alone can be replayed. The confirmation frame cannot: it is sealed
// under a key that depends on the relay's fresh ephemeral from message 2.

/** Separates this use of the identity key from the pairing and open handshakes. */
export const TUNNEL_PROLOGUE = Buffer.from("threadbase-relay/1 tunnel", "utf-8");
const ROUTE_DOMAIN = Buffer.from("threadbase-relay/1 route", "utf-8");
const CONFIRM_PLAINTEXT = Buffer.from("threadbase-relay/1 confirm", "utf-8");
const CONFIRM_NONCE = Buffer.alloc(12);
const TAG_BYTES = 16;

export const RELAY_PROTOCOL_VERSIONS = [1] as const;
export const RELAY_CAPABILITIES = ["http", "ws"] as const;
export const ROUTE_ID_CHARS = 32;

export class UnsupportedProtocolError extends Error {}

/** A locator, not a credential: 192 bits of `sha256(domain || spk)`, base64url. */
export function routeIdFromStreamerKey(streamerStaticPub: Buffer): string {
  return createHash("sha256")
    .update(ROUTE_DOMAIN)
    .update(streamerStaticPub)
    .digest("base64url")
    .slice(0, ROUTE_ID_CHARS);
}

export interface TunnelOffer {
  protocols: number[];
  caps: string[];
}

export interface TunnelHello {
  protocol: number;
  caps: string[];
  tunnelId: string;
  limits: Record<string, number>;
}

function sealConfirm(key: KeyObject, handshakeHash: Buffer): Buffer {
  const cipher = createCipheriv("chacha20-poly1305", key, CONFIRM_NONCE, { authTagLength: TAG_BYTES });
  cipher.setAAD(handshakeHash, { plaintextLength: CONFIRM_PLAINTEXT.length });
  return Buffer.concat([cipher.update(CONFIRM_PLAINTEXT), cipher.final(), cipher.getAuthTag()]);
}

function confirmIsValid(key: KeyObject, handshakeHash: Buffer, frame: Buffer): boolean {
  if (frame.length !== CONFIRM_PLAINTEXT.length + TAG_BYTES) return false;
  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, CONFIRM_NONCE, { authTagLength: TAG_BYTES });
    decipher.setAAD(handshakeHash, { plaintextLength: CONFIRM_PLAINTEXT.length });
    decipher.setAuthTag(frame.subarray(CONFIRM_PLAINTEXT.length));
    const plaintext = Buffer.concat([decipher.update(frame.subarray(0, CONFIRM_PLAINTEXT.length)), decipher.final()]);
    return plaintext.equals(CONFIRM_PLAINTEXT);
  } catch {
    return false;
  }
}

function parseOffer(payload: Buffer): TunnelOffer {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload.toString("utf-8"));
  } catch {
    throw new NoiseError("Tunnel offer is not JSON");
  }
  const offer = parsed as Partial<TunnelOffer> | null;
  if (!offer || !Array.isArray(offer.protocols) || !Array.isArray(offer.caps)) {
    throw new NoiseError("Tunnel offer is malformed");
  }
  return { protocols: offer.protocols.filter(Number.isInteger), caps: offer.caps.map(String) };
}

export interface AcceptedTunnel {
  routeId: string;
  message2: Buffer;
  /** True only for the confirmation frame of THIS handshake. */
  confirm(frame: Buffer): boolean;
}

/**
 * Relay side. Throws `NoiseError` when message 1 does not authenticate and
 * `UnsupportedProtocolError` when it does but offers no protocol we speak.
 */
export function acceptTunnel(args: {
  relayKeyPair: KeyPair;
  message1: Buffer;
  tunnelId: string;
  limits: Record<string, number>;
}): AcceptedTunnel {
  const state = readMessage1({
    staticKeyPair: args.relayKeyPair,
    pattern: "IK",
    message1: args.message1,
    prologue: TUNNEL_PROLOGUE,
  });
  const offer = parseOffer(state.payload);
  const protocol = Math.max(
    -1,
    ...offer.protocols.filter((v) => (RELAY_PROTOCOL_VERSIONS as readonly number[]).includes(v)),
  );
  if (protocol < 0) throw new UnsupportedProtocolError("No common relay protocol version");

  const hello: TunnelHello = {
    protocol,
    caps: RELAY_CAPABILITIES.filter((cap) => offer.caps.includes(cap)),
    tunnelId: args.tunnelId,
    limits: args.limits,
  };
  const routeId = routeIdFromStreamerKey(state.initiatorStaticPub);
  const { message2, keys } = writeMessage2(state, Buffer.from(JSON.stringify(hello), "utf-8"));
  const { clientToServer, handshakeHash } = keys.consume();
  return { routeId, message2, confirm: (frame) => confirmIsValid(clientToServer, handshakeHash, frame) };
}

/**
 * Streamer side. Lives here so the relay's tests drive the responder with the
 * same initiator the streamer's connector mirrors, not a second one that drifts.
 */
export function initiateTunnel(args: {
  streamerKeyPair: KeyPair;
  relayStaticPub: Buffer;
  offer?: TunnelOffer;
}): { message1: Buffer; state: HandshakeInitiatorState } {
  const offer = args.offer ?? { protocols: [...RELAY_PROTOCOL_VERSIONS], caps: [...RELAY_CAPABILITIES] };
  const { message, state } = writeMessage1({
    staticKeyPair: args.streamerKeyPair,
    responderStaticPub: args.relayStaticPub,
    pattern: "IK",
    payload: Buffer.from(JSON.stringify(offer), "utf-8"),
    prologue: TUNNEL_PROLOGUE,
  });
  return { message1: message, state };
}

export function completeTunnel(
  state: HandshakeInitiatorState,
  message2: Buffer,
): { hello: TunnelHello; confirmFrame: Buffer } {
  const { payload, keys } = readMessage2(state, message2);
  const { clientToServer, handshakeHash } = keys.consume();
  return {
    hello: JSON.parse(payload.toString("utf-8")) as TunnelHello,
    confirmFrame: sealConfirm(clientToServer, handshakeHash),
  };
}
