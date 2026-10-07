import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import { encodeCredit } from "../src/flow";
import { decodeFrame, encodeFrame, type Frame, FRAME_TYPES } from "../src/frames";
import { generateKeyPair } from "../src/noise/noise";
import { createConcurrencyLimit } from "../src/rate-limit";
import { createRelay, type RATE_LIMITS, type Relay } from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey } from "../src/tunnel-auth";

// Each cap is shown admitting up to its value before refusing past it, so a
// refusal here cannot be a harness that refuses everything.

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

const until = async (condition: () => boolean) => {
  for (let i = 0; i < 400 && !condition(); i++) await new Promise((r) => setTimeout(r, 5));
};

async function streamer(onFrame: (frame: Frame, ws: WebSocket) => void = () => {}) {
  const keyPair = generateKeyPair();
  const ws = new WebSocket(`ws://${base}/tunnel`);
  sockets.push(ws);
  await new Promise((resolve) => ws.once("open", resolve));
  const { message1, state } = initiateTunnel({ streamerKeyPair: keyPair, relayStaticPub: relayKeyPair.publicKeyRaw });
  ws.send(message1);
  const message2 = await new Promise<Buffer>((resolve) => ws.once("message", (d) => resolve(d as Buffer)));
  ws.send(completeTunnel(state, message2).confirmFrame);
  const routeId = routeIdFromStreamerKey(keyPair.publicKeyRaw);
  await until(() => Boolean(relay.registry.get(routeId)));
  const frames: Frame[] = [];
  ws.on("message", (data) => {
    const frame = decodeFrame(data as Buffer);
    frames.push(frame);
    onFrame(frame, ws);
  });
  return { routeId, frames };
}

/** Grants what it receives and answers each request with 10 bytes once it ends. */
function echo(frame: Frame, ws: WebSocket): void {
  if (frame.type === FRAME_TYPES.DATA) {
    ws.send(encodeFrame(FRAME_TYPES.WINDOW, frame.streamId, encodeCredit(frame.payload.length)));
  }
  if (frame.type !== FRAME_TYPES.END) return;
  ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify({ status: 200, headers: {} }))));
  ws.send(encodeFrame(FRAME_TYPES.DATA, frame.streamId, Buffer.from("ciphertext")));
  ws.send(encodeFrame(FRAME_TYPES.END, frame.streamId));
}

const SEALED = { "x-tb-ctx": "ctx-1" };
const count = (frames: Frame[], type: number) => frames.filter((f) => f.type === type).length;
const refusedWith = (ws: WebSocket) =>
  new Promise<number | undefined>((resolve) => {
    ws.once("unexpected-response", (_req, res) => resolve(res.statusCode));
    ws.once("open", () => resolve(undefined));
    ws.on("error", () => {});
  });

describe("createConcurrencyLimit", () => {
  it("holds a key to its cap and frees a slot on release", () => {
    const limit = createConcurrencyLimit(2);
    expect([limit.acquire("a"), limit.acquire("a"), limit.acquire("a")]).toEqual([true, true, false]);
    expect(limit.acquire("b")).toBe(true);
    limit.release("a");
    expect(limit.acquire("a")).toBe(true);
  });
});

describe("connection caps", () => {
  it("holds a client address to its open requests and frees a slot when one ends", async () => {
    await start({ clientConnections: 2 });
    const s = await streamer();
    const pending = [new AbortController(), new AbortController()].map((c) => ({
      c,
      done: fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: SEALED, signal: c.signal }).catch(() => null),
    }));
    await until(() => count(s.frames, FRAME_TYPES.OPEN) === 2);

    const refused = await fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: SEALED });
    expect(refused.status).toBe(503);
    expect(refused.headers.get("x-tb-relay-error")).toBe("1");
    expect((await refused.json()).code).toBe("RELAY_OVERLOADED");
    expect(count(s.frames, FRAME_TYPES.OPEN)).toBe(2);

    pending[0].c.abort();
    await pending[0].done;
    await until(() => count(s.frames, FRAME_TYPES.RESET) === 1);
    const freed = new AbortController();
    void fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: SEALED, signal: freed.signal }).catch(() => null);
    await until(() => count(s.frames, FRAME_TYPES.OPEN) === 3);
    expect(count(s.frames, FRAME_TYPES.OPEN)).toBe(3);
    freed.abort();
    pending[1].c.abort();
  });

  it("holds one address to its open tunnels and frees a slot when one closes", async () => {
    await start({ tunnelConnections: 2 });
    const dial = () => {
      const ws = new WebSocket(`ws://${base}/tunnel`);
      sockets.push(ws);
      return ws;
    };
    const first = dial();
    expect(await refusedWith(first)).toBeUndefined();
    expect(await refusedWith(dial())).toBeUndefined();
    expect(await refusedWith(dial())).toBe(503);

    first.terminate();
    await new Promise((r) => setTimeout(r, 50));
    expect(await refusedWith(dial())).toBeUndefined();
  });
});

describe("route byte quota", () => {
  it("serves a route up to its quota, cuts the request that crosses it, then refuses with Retry-After", async () => {
    await start({ routeBytesPerDay: 1000 });
    const s = await streamer(echo);
    const post = () =>
      fetch(`http://${base}/r/${s.routeId}/api/x`, { method: "POST", headers: SEALED, body: Buffer.alloc(600, 1) });

    expect((await post()).status).toBe(200);

    const crossing = await post();
    expect(crossing.status).toBe(429);
    expect((await crossing.json()).code).toBe("RELAY_RATE_LIMITED");
    expect(count(s.frames, FRAME_TYPES.RESET)).toBe(1);

    const opened = count(s.frames, FRAME_TYPES.OPEN);
    const refused = await fetch(`http://${base}/r/${s.routeId}/api/info`, { headers: SEALED });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("x-tb-relay-error")).toBe("1");
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(count(s.frames, FRAME_TYPES.OPEN)).toBe(opened);
  });

  it("cuts a download that crosses the quota", async () => {
    await start({ routeBytesPerDay: 1000 });
    const s = await streamer((frame, ws) => {
      if (frame.type !== FRAME_TYPES.END) return;
      ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify({ status: 200, headers: {} }))));
      for (let i = 0; i < 3; i++) ws.send(encodeFrame(FRAME_TYPES.DATA, frame.streamId, Buffer.alloc(400, i)));
      ws.send(encodeFrame(FRAME_TYPES.END, frame.streamId));
    });
    // The cut can land before or after the head reaches the client; either way no complete body does.
    const body = fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: SEALED }).then((res) => res.arrayBuffer());
    await expect(body).rejects.toThrow();
    await until(() => count(s.frames, FRAME_TYPES.RESET) === 1);
    expect(count(s.frames, FRAME_TYPES.RESET)).toBe(1);
  });

  it("closes an open socket once its route spends the quota, and refuses the next one", async () => {
    await start({ routeBytesPerDay: 1000 });
    const s = await streamer((frame, ws) => {
      if (frame.type === FRAME_TYPES.OPEN) {
        ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify({ accepted: true }))));
      } else if (frame.type === FRAME_TYPES.DATA) {
        ws.send(encodeFrame(FRAME_TYPES.WINDOW, frame.streamId, encodeCredit(frame.payload.length - 1)));
        ws.send(encodeFrame(FRAME_TYPES.DATA, frame.streamId, frame.payload));
      }
    });
    const dial = () => {
      const ws = new WebSocket(`ws://${base}/r/${s.routeId}/ws`, { headers: { "x-tb-ticket": "t" } });
      sockets.push(ws);
      return ws;
    };
    const ws = dial();
    await new Promise((resolve) => ws.once("open", resolve));
    const closed = new Promise<{ code: number; reason: string }>((resolve) =>
      ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })),
    );
    const echoed: Buffer[] = [];
    ws.on("message", (data) => echoed.push(data as Buffer));

    // 400 out and 400 back fits; the next 400 out crosses 1000.
    ws.send(Buffer.alloc(400, 1));
    await until(() => echoed.length === 1);
    expect(echoed).toHaveLength(1);
    ws.send(Buffer.alloc(400, 2));
    expect(await closed).toEqual({ code: 1013, reason: "RELAY_RATE_LIMITED" });
    expect(count(s.frames, FRAME_TYPES.RESET)).toBe(1);
    expect(count(s.frames, FRAME_TYPES.DATA)).toBe(1);

    expect(await refusedWith(dial())).toBe(429);
  });
});
