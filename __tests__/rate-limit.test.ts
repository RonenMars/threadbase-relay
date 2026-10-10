import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import { generateKeyPair, type KeyPair } from "../src/noise/noise";
import { createRateLimiter } from "../src/rate-limit";
import { CLOSE_RATE_LIMITED, createRelay, RATE_LIMITS, type Relay } from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey } from "../src/tunnel-auth";

// Each limit is shown holding at its value and refusing one past it, so a
// refusal here cannot be a harness that refuses everything.

describe("createRateLimiter", () => {
  it("allows the limit, refuses past it, and starts over in the next window", () => {
    let t = 0;
    const limiter = createRateLimiter(2, 60_000, () => t);
    expect([limiter.take("a"), limiter.take("a")]).toEqual([0, 0]);
    expect(limiter.take("a")).toBe(60);
    expect(limiter.take("b")).toBe(0);
    t = 45_000;
    expect(limiter.take("a")).toBe(15);
    t = 60_000;
    expect(limiter.take("a")).toBe(0);
  });
});

const relayKeyPair = generateKeyPair();
let relay: Relay;
let base: string;
const sockets: WebSocket[] = [];

async function start(rateLimits: Partial<typeof RATE_LIMITS>): Promise<void> {
  relay = createRelay({ relayKeyPair, rateLimits });
  await new Promise<void>((resolve) => relay.server.listen(0, "127.0.0.1", resolve));
  base = `127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
}
afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.terminate();
  if (!relay) return;
  relay.server.closeAllConnections();
  await new Promise((resolve) => relay.server.close(resolve));
});

/** Dials and authenticates; resolves with the socket once attached or closed. */
async function attach(streamer: KeyPair): Promise<{ ws: WebSocket; closed: Promise<number> }> {
  const ws = new WebSocket(`ws://${base}/tunnel`);
  sockets.push(ws);
  const closed = new Promise<number>((resolve) => ws.once("close", resolve));
  await new Promise((resolve) => ws.once("open", resolve));
  const { message1, state } = initiateTunnel({ streamerKeyPair: streamer, relayStaticPub: relayKeyPair.publicKeyRaw });
  ws.send(message1);
  const message2 = await new Promise<Buffer>((resolve) => ws.once("message", (d) => resolve(d as Buffer)));
  ws.send(completeTunnel(state, message2).confirmFrame);
  return { ws, closed };
}

const until = async (condition: () => boolean) => {
  for (let i = 0; i < 200 && !condition(); i++) await new Promise((r) => setTimeout(r, 5));
};

describe("relay rate limits", () => {
  it("answers a client past its request limit with a marked 429 and Retry-After", async () => {
    await start({ clientRequests: 3 });
    const call = () => fetch(`http://${base}/r/${"a".repeat(32)}/api/info`, { headers: { "x-tb-ctx": "c" } });
    for (let i = 0; i < 3; i++) expect((await call()).status).toBe(503);
    const limited = await call();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("x-tb-relay-error")).toBe("1");
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await limited.json()).code).toBe("RELAY_RATE_LIMITED");
  });

  it("counts client sockets against the same limit", async () => {
    await start({ clientRequests: 1 });
    await fetch(`http://${base}/r/${"a".repeat(32)}/api/info`, { headers: { "x-tb-ctx": "c" } });
    const ws = new WebSocket(`ws://${base}/r/${"a".repeat(32)}/ws`, { headers: { "x-tb-ticket": "t" } });
    sockets.push(ws);
    ws.on("error", () => {});
    const status = await new Promise<number>((resolve) => ws.once("unexpected-response", (_req, res) => resolve(res.statusCode ?? 0)));
    expect(status).toBe(429);
  });

  it("refuses tunnel dials past the handshake limit", async () => {
    await start({ tunnelHandshakes: 2 });
    for (let i = 0; i < 2; i++) await attach(generateKeyPair());
    const ws = new WebSocket(`ws://${base}/tunnel`);
    sockets.push(ws);
    ws.on("error", () => {});
    const status = await new Promise<number>((resolve) => ws.once("unexpected-response", (_req, res) => resolve(res.statusCode ?? 0)));
    expect(status).toBe(429);
  });

  it("keeps the serving tunnel when its route is replaced too often", async () => {
    await start({ tunnelReplacements: 1 });
    const streamer = generateKeyPair();
    const routeId = routeIdFromStreamerKey(streamer.publicKeyRaw);
    await attach(streamer);
    await until(() => relay.registry.size === 1);
    const first = relay.registry.get(routeId);

    // One replacement is allowed and takes the route over.
    await attach(streamer);
    await until(() => relay.registry.get(routeId) !== first);
    const serving = relay.registry.get(routeId);
    expect(serving).toBeDefined();
    expect(serving).not.toBe(first);

    const refused = await attach(streamer);
    expect(await refused.closed).toBe(CLOSE_RATE_LIMITED);
    expect(relay.registry.get(routeId)).toBe(serving);
  });
});
