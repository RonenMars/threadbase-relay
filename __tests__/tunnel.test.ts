import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import { encodeFrame, FRAME_TYPES, MAX_FRAME_BYTES } from "../src/frames";
import { generateKeyPair, type KeyPair } from "../src/noise/noise";
import { CLOSE_REPLACED } from "../src/registry";
import {
  CLOSE_AUTH_FAILED,
  CLOSE_HANDSHAKE_TIMEOUT,
  CLOSE_MALFORMED,
  CLOSE_UNSUPPORTED_PROTOCOL,
  createRelay,
  type Relay,
} from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey, type TunnelHello } from "../src/tunnel-auth";

// The properties under test are the ones a public relay exists to guarantee:
// a route can only be attached by the holder of the key it is derived from, and
// a connection that lost its route never gets it back. Every refusal here has a
// positive control in the same file (the first test), so "it was refused" cannot
// be a harness that refuses everything.

const relayKeyPair = generateKeyPair();
let relay: Relay;
let url: string;
const sockets: WebSocket[] = [];

async function startRelay(handshakeTimeoutMs?: number): Promise<void> {
  relay = createRelay({ relayKeyPair, handshakeTimeoutMs });
  await new Promise<void>((resolve) => relay.server.listen(0, "127.0.0.1", resolve));
  url = `127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
}

beforeEach(() => startRelay());
afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.terminate();
  await new Promise((resolve) => relay.server.close(resolve));
});

function dial(): Promise<WebSocket> {
  const ws = new WebSocket(`ws://${url}/tunnel`);
  sockets.push(ws);
  return new Promise((resolve, reject) => {
    ws.once("open", () => resolve(ws));
    ws.once("error", reject);
  });
}

const nextMessage = (ws: WebSocket) =>
  new Promise<Buffer>((resolve) => ws.once("message", (data) => resolve(data as Buffer)));
const closed = (ws: WebSocket) => new Promise<number>((resolve) => ws.once("close", (code) => resolve(code)));

async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 200 && !condition(); i++) await new Promise((r) => setTimeout(r, 5));
  expect(condition()).toBe(true);
}

/** A full, honest handshake. Resolves once the relay has attached the route. */
async function attach(streamer: KeyPair): Promise<{ ws: WebSocket; hello: TunnelHello; routeId: string }> {
  const ws = await dial();
  const { message1, state } = initiateTunnel({ streamerKeyPair: streamer, relayStaticPub: relayKeyPair.publicKeyRaw });
  ws.send(message1);
  const { hello, confirmFrame } = completeTunnel(state, await nextMessage(ws));
  ws.send(confirmFrame);
  const routeId = routeIdFromStreamerKey(streamer.publicKeyRaw);
  await until(() => relay.registry.get(routeId)?.id === hello.tunnelId);
  return { ws, hello, routeId };
}

describe("tunnel authentication", () => {
  it("attaches a streamer to the route derived from its own key", async () => {
    const streamer = generateKeyPair();
    const { hello, routeId } = await attach(streamer);

    expect(routeId).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(hello.protocol).toBe(1);
    expect(hello.caps).toEqual(["http", "ws"]);
    expect(relay.registry.size).toBe(1);
  });

  it("refuses a streamer that dialled with the wrong relay key", async () => {
    const ws = await dial();
    const { message1 } = initiateTunnel({
      streamerKeyPair: generateKeyPair(),
      relayStaticPub: generateKeyPair().publicKeyRaw,
    });
    ws.send(message1);

    expect(await closed(ws)).toBe(CLOSE_AUTH_FAILED);
    expect(relay.registry.size).toBe(0);
  });

  it("gives streamer B its own route, never streamer A's", async () => {
    const a = await attach(generateKeyPair());
    const b = await attach(generateKeyPair());

    expect(b.routeId).not.toBe(a.routeId);
    expect(relay.registry.get(a.routeId)?.id).toBe(a.hello.tunnelId);
    expect(relay.registry.get(b.routeId)?.id).toBe(b.hello.tunnelId);
    expect(a.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("refuses a replayed message 1, because the replayer cannot confirm", async () => {
    const streamer = generateKeyPair();
    const { message1, state } = initiateTunnel({
      streamerKeyPair: streamer,
      relayStaticPub: relayKeyPair.publicKeyRaw,
    });
    const honest = await dial();
    honest.send(message1);
    const { hello, confirmFrame } = completeTunnel(state, await nextMessage(honest));
    honest.send(confirmFrame);
    const routeId = routeIdFromStreamerKey(streamer.publicKeyRaw);
    await until(() => relay.registry.get(routeId)?.id === hello.tunnelId);

    // The attacker saw everything the streamer sent and sends it all again.
    const attacker = await dial();
    attacker.send(message1);
    await nextMessage(attacker);
    attacker.send(confirmFrame);

    expect(await closed(attacker)).toBe(CLOSE_AUTH_FAILED);
    expect(relay.registry.get(routeId)?.id).toBe(hello.tunnelId);
    expect(honest.readyState).toBe(WebSocket.OPEN);
  });

  it("refuses a tampered message 1", async () => {
    const ws = await dial();
    const { message1 } = initiateTunnel({
      streamerKeyPair: generateKeyPair(),
      relayStaticPub: relayKeyPair.publicKeyRaw,
    });
    message1[40] ^= 1; // inside the encrypted static key
    ws.send(message1);

    expect(await closed(ws)).toBe(CLOSE_AUTH_FAILED);
    expect(relay.registry.size).toBe(0);
  });

  it("tells an authenticated streamer when no protocol version is shared", async () => {
    const ws = await dial();
    const { message1 } = initiateTunnel({
      streamerKeyPair: generateKeyPair(),
      relayStaticPub: relayKeyPair.publicKeyRaw,
      offer: { protocols: [99], caps: ["http"] },
    });
    ws.send(message1);

    expect(await closed(ws)).toBe(CLOSE_UNSUPPORTED_PROTOCOL);
    expect(relay.registry.size).toBe(0);
  });

  it("drops a connection that never finishes the handshake", async () => {
    await new Promise((resolve) => relay.server.close(resolve));
    await startRelay(50);
    const ws = await dial();

    expect(await closed(ws)).toBe(CLOSE_HANDSHAKE_TIMEOUT);
  });
});

describe("stale connections", () => {
  it("replaces the old tunnel on reconnect and never routes to it again", async () => {
    const streamer = generateKeyPair();
    const first = await attach(streamer);
    const firstClosed = closed(first.ws);
    const second = await attach(streamer);

    expect(await firstClosed).toBe(CLOSE_REPLACED);
    expect(second.hello.tunnelId).not.toBe(first.hello.tunnelId);
    // The old socket has now closed; its late close must not evict the new tunnel.
    expect(relay.registry.get(second.routeId)?.id).toBe(second.hello.tunnelId);
    expect(second.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("frees the route when its tunnel disconnects", async () => {
    const { ws, routeId } = await attach(generateKeyPair());
    ws.close();
    await until(() => relay.registry.get(routeId) === undefined);
  });
});

describe("frames on an attached tunnel", () => {
  it("keeps the tunnel for a well-formed frame", async () => {
    const { ws, routeId } = await attach(generateKeyPair());
    ws.send(encodeFrame(FRAME_TYPES.DATA, 7, Buffer.from("x")));
    ws.ping();
    await new Promise((resolve) => ws.once("pong", resolve));

    expect(relay.registry.get(routeId)).toBeDefined();
  });

  it.each([
    ["an unknown frame type", Buffer.from([99, 0, 0, 0, 1])],
    ["a truncated frame", Buffer.from([FRAME_TYPES.DATA, 0])],
  ])("closes the tunnel and frees the route on %s", async (_name, bytes) => {
    const { ws, routeId } = await attach(generateKeyPair());
    ws.send(bytes);

    expect(await closed(ws)).toBe(CLOSE_MALFORMED);
    await until(() => relay.registry.get(routeId) === undefined);
  });

  it("closes the tunnel on a frame over the size cap", async () => {
    const { ws, routeId } = await attach(generateKeyPair());
    ws.send(Buffer.alloc(MAX_FRAME_BYTES + 1));

    expect(await closed(ws)).toBe(1009);
    await until(() => relay.registry.get(routeId) === undefined);
  });
});

describe("http surface", () => {
  it("answers /healthz", async () => {
    const res = await fetch(`http://${url}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true });
  });

  it("answers an unsealed probe identically for an attached and an unknown route", async () => {
    const { routeId } = await attach(generateKeyPair());
    const known = await fetch(`http://${url}/r/${routeId}/api/info`);
    const unknown = await fetch(`http://${url}/r/${"A".repeat(32)}/api/info`);

    for (const res of [known, unknown]) {
      expect(res.status).toBe(400);
      expect(res.headers.get("x-tb-relay-error")).toBe("1");
    }
    expect(await known.text()).toBe(await unknown.text());
  });

  it("never answers 403 or 404, which a client reads as a permanent streamer refusal", async () => {
    const res = await fetch(`http://${url}/nope`);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ code: "RELAY_UNSUPPORTED_REQUEST" });
  });

  it("refuses a WebSocket upgrade anywhere but the tunnel path", async () => {
    const ws = new WebSocket(`ws://${url}/r/abc/ws`);
    sockets.push(ws);
    await new Promise((resolve) => ws.once("error", resolve));
    expect(ws.readyState).not.toBe(WebSocket.OPEN);
  });
});
