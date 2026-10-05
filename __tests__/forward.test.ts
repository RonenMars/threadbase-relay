import { request as httpRequest } from "http";
import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import {
  createFlowReceiver,
  createFlowSender,
  encodeCredit,
  FlowError,
  parseCredit,
  STREAM_WINDOW_BYTES,
} from "../src/flow";
import { decodeFrame, encodeFrame, type Frame, FRAME_TYPES } from "../src/frames";
import { generateKeyPair } from "../src/noise/noise";
import { createRelay, type Relay } from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey } from "../src/tunnel-auth";

// A client request reaches the streamer that owns the route and nobody else,
// and the relay carries only requests that are sealed. The first test is the
// positive control for every refusal below it.

const relayKeyPair = generateKeyPair();
let relay: Relay;
let base: string;
const sockets: WebSocket[] = [];

beforeEach(async () => {
  relay = createRelay({ relayKeyPair });
  await new Promise<void>((resolve) => relay.server.listen(0, "127.0.0.1", resolve));
  base = `127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.terminate();
  relay.server.closeAllConnections();
  await new Promise((resolve) => relay.server.close(resolve));
});

interface FakeStreamer {
  ws: WebSocket;
  routeId: string;
  frames: Frame[];
}

/** Attaches a streamer whose behaviour per frame is `onFrame`. */
async function streamer(onFrame: (frame: Frame, ws: WebSocket) => void = () => {}): Promise<FakeStreamer> {
  const keyPair = generateKeyPair();
  const ws = new WebSocket(`ws://${base}/tunnel`);
  sockets.push(ws);
  await new Promise((resolve) => ws.once("open", resolve));
  const { message1, state } = initiateTunnel({ streamerKeyPair: keyPair, relayStaticPub: relayKeyPair.publicKeyRaw });
  ws.send(message1);
  const message2 = await new Promise<Buffer>((resolve) => ws.once("message", (d) => resolve(d as Buffer)));
  ws.send(completeTunnel(state, message2).confirmFrame);
  const routeId = routeIdFromStreamerKey(keyPair.publicKeyRaw);
  for (let i = 0; i < 200 && !relay.registry.get(routeId); i++) await new Promise((r) => setTimeout(r, 5));
  const frames: Frame[] = [];
  ws.on("message", (data) => {
    const frame = decodeFrame(data as Buffer);
    frames.push(frame);
    onFrame(frame, ws);
  });
  return { ws, routeId, frames };
}

/** Echoes the request body back as the response once the request ends. */
function echo(frame: Frame, ws: WebSocket): void {
  if (frame.type === FRAME_TYPES.DATA) {
    ws.send(encodeFrame(FRAME_TYPES.WINDOW, frame.streamId, encodeCredit(frame.payload.length)));
  }
  if (frame.type !== FRAME_TYPES.END) return;
  const head = { status: 200, headers: { "x-tb-env": "sealed", "set-cookie": "leak=1" } };
  ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify(head))));
  ws.send(encodeFrame(FRAME_TYPES.DATA, frame.streamId, Buffer.from("ciphertext")));
  ws.send(encodeFrame(FRAME_TYPES.END, frame.streamId));
}

const SEALED = { "x-tb-ctx": "ctx-1" };
const call = (routeId: string, path: string, init?: RequestInit) => fetch(`http://${base}/r/${routeId}${path}`, init);

describe("forwarding", () => {
  it("carries a sealed request to the streamer and its response back", async () => {
    const s = await streamer(echo);
    const res = await call(s.routeId, "/api/info?x=1", { headers: { ...SEALED, cookie: "a=b", "user-agent": "tb" } });

    expect(res.status).toBe(200);
    expect(res.headers.get("x-tb-relay-error")).toBeNull();
    expect(res.headers.get("x-tb-env")).toBe("sealed");
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(await res.text()).toBe("ciphertext");

    const open = JSON.parse(s.frames[0].payload.toString());
    expect(s.frames[0].type).toBe(FRAME_TYPES.OPEN);
    expect(open).toMatchObject({ kind: "http", method: "GET", target: "/api/info?x=1", headers: { "x-tb-ctx": "ctx-1" } });
    // Only the allowlist crosses: nothing that identifies the client or its browser.
    expect(Object.keys(open.headers).sort()).toEqual(["accept", "x-tb-ctx"]);
    expect(open.clientTag).toMatch(/^[A-Za-z0-9_-]{16}$/);
  });

  it("derives the client tag from the connection, not from a header the client chose", async () => {
    const s = await streamer(echo);
    for (const spoof of ["1.1.1.1", "2.2.2.2"]) {
      await call(s.routeId, "/api/info", { headers: { ...SEALED, "x-forwarded-for": spoof, "x-real-ip": spoof, "fly-client-ip": spoof } });
    }
    const tags = s.frames.filter((f) => f.type === FRAME_TYPES.OPEN).map((f) => JSON.parse(f.payload.toString()).clientTag);
    expect(tags).toHaveLength(2);
    expect(tags[0]).toBe(tags[1]);
  });

  it("forwards a request body as opaque bytes", async () => {
    const s = await streamer(echo);
    const body = Buffer.alloc(200_000, 7);
    await call(s.routeId, "/api/x", { method: "POST", headers: SEALED, body });

    const data = s.frames.filter((f) => f.type === FRAME_TYPES.DATA);
    expect(data.length).toBeGreaterThan(1);
    expect(Buffer.concat(data.map((f) => f.payload)).equals(body)).toBe(true);
  });

  it("sends no more of an upload than the streamer has granted", async () => {
    // A streamer that never grants credit: the relay must stop at the window.
    const s = await streamer();
    const sent = () => s.frames.filter((f) => f.type === FRAME_TYPES.DATA).reduce((n, f) => n + f.payload.length, 0);
    const pending = call(s.routeId, "/api/x", { method: "POST", headers: SEALED, body: Buffer.alloc(1_000_000) });
    for (let i = 0; i < 200 && sent() < STREAM_WINDOW_BYTES; i++) await new Promise((r) => setTimeout(r, 5));
    await new Promise((r) => setTimeout(r, 100));
    expect(sent()).toBe(STREAM_WINDOW_BYTES);
    expect(s.frames.some((f) => f.type === FRAME_TYPES.END)).toBe(false);

    // Granting the rest lets it finish.
    const id = s.frames[0].streamId;
    s.ws.on("message", (data) => echo(decodeFrame(data as Buffer), s.ws));
    s.ws.send(encodeFrame(FRAME_TYPES.WINDOW, id, encodeCredit(STREAM_WINDOW_BYTES)));
    expect((await pending).status).toBe(200);
    expect(sent()).toBe(1_000_000);
  });

  it("grants credit for a response as the client takes it", async () => {
    const big = await streamer((f, ws) => {
      if (f.type !== FRAME_TYPES.END) return;
      ws.send(encodeFrame(FRAME_TYPES.HEAD, f.streamId, Buffer.from(JSON.stringify({ status: 200, headers: {} }))));
      for (let i = 0; i < 4; i++) ws.send(encodeFrame(FRAME_TYPES.DATA, f.streamId, Buffer.alloc(65536, 1)));
    });
    const windows = () => big.frames.filter((f) => f.type === FRAME_TYPES.WINDOW);
    const ok = await call(big.routeId, "/api/info", { headers: SEALED });
    const body = ok.arrayBuffer();
    for (let i = 0; i < 200 && windows().length < 4; i++) await new Promise((r) => setTimeout(r, 5));
    big.ws.send(encodeFrame(FRAME_TYPES.END, big.frames[0].streamId));
    expect((await body).byteLength).toBe(4 * 65536);
    const granted = windows();
    expect(granted.map((f) => JSON.parse(f.payload.toString()).credit)).toEqual([65536, 65536, 65536, 65536]);
  });

  it("refuses a body that declares more than the largest upload", async () => {
    const s = await streamer(echo);
    const res = await new Promise<number>((resolve) => {
      const req = httpRequest(`http://${base}/r/${s.routeId}/api/x`, { method: "POST", headers: { ...SEALED, "content-length": String(70 * 1024 * 1024) } }, (r) => resolve(r.statusCode ?? 0));
      req.on("error", () => {});
      req.flushHeaders();
    });
    expect(res).toBe(400);
    expect(s.frames).toEqual([]);
  });

  it("carries the two handshakes without a context", async () => {
    const s = await streamer(echo);
    expect((await call(s.routeId, "/api/e2ee/open", { method: "POST", body: "m1" })).status).toBe(200);
    expect((await call(s.routeId, "/api/pair/exchange", { method: "POST", body: "m1" })).status).toBe(200);
  });

  it("refuses an unsealed request and never writes it to the tunnel", async () => {
    const s = await streamer(echo);
    for (const res of [
      await call(s.routeId, "/api/info"),
      await call(s.routeId, "/api/e2ee/open"),
      await call(s.routeId, "/api/info", { headers: { ...SEALED, authorization: "Bearer tb_x" } }),
      await call(s.routeId, "/api/info?key=tb_x", { headers: SEALED }),
    ]) {
      expect(res.status).toBe(400);
      expect(res.headers.get("x-tb-relay-error")).toBe("1");
      expect(((await res.json()) as { code: string }).code).toBe("RELAY_UNSUPPORTED_REQUEST");
    }
    expect(s.frames).toEqual([]);
  });

  it("delivers a request only to the streamer that owns the route", async () => {
    const a = await streamer(echo);
    const b = await streamer(echo);
    await call(a.routeId, "/api/info", { headers: SEALED });

    expect(a.frames.length).toBeGreaterThan(0);
    expect(b.frames).toEqual([]);
  });

  it("answers an unknown route exactly as an offline one", async () => {
    const s = await streamer(echo);
    s.ws.terminate();
    for (let i = 0; i < 200 && relay.registry.get(s.routeId); i++) await new Promise((r) => setTimeout(r, 5));

    const offline = await call(s.routeId, "/api/info", { headers: SEALED });
    const unknown = await call("A".repeat(32), "/api/info", { headers: SEALED });
    expect(offline.status).toBe(503);
    expect(unknown.status).toBe(503);
    expect(await unknown.text()).toBe(await offline.text());
  });

  it("resets an in-flight request when its tunnel dies", async () => {
    const s = await streamer((frame, ws) => {
      if (frame.type === FRAME_TYPES.END) ws.terminate();
    });
    const res = await call(s.routeId, "/api/info", { headers: SEALED });

    expect(res.status).toBe(502);
    expect(((await res.json()) as { code: string }).code).toBe("RELAY_STREAM_RESET");
  });

  it("maps a streamer RESET and a malformed HEAD to a marked 502", async () => {
    const reset = await streamer((f, ws) => {
      if (f.type === FRAME_TYPES.END) ws.send(encodeFrame(FRAME_TYPES.RESET, f.streamId));
    });
    const junk = await streamer((f, ws) => {
      if (f.type === FRAME_TYPES.END) ws.send(encodeFrame(FRAME_TYPES.HEAD, f.streamId, Buffer.from("{")));
    });
    for (const s of [reset, junk]) {
      const res = await call(s.routeId, "/api/info", { headers: SEALED });
      expect(res.status).toBe(502);
      expect(res.headers.get("x-tb-relay-error")).toBe("1");
    }
  });

  it("refuses new requests at the stream limit and recovers when one ends", async () => {
    const held: number[] = [];
    const s = await streamer((f) => {
      if (f.type === FRAME_TYPES.END) held.push(f.streamId);
    });
    const pending = Array.from({ length: 64 }, () => call(s.routeId, "/api/info", { headers: SEALED }));
    for (let i = 0; i < 400 && held.length < 64; i++) await new Promise((r) => setTimeout(r, 5));
    expect(held).toHaveLength(64);

    const over = await call(s.routeId, "/api/info", { headers: SEALED });
    expect(over.status).toBe(503);
    expect(((await over.json()) as { code: string }).code).toBe("RELAY_OVERLOADED");

    for (const id of held) echo({ type: FRAME_TYPES.END, streamId: id, payload: Buffer.alloc(0) }, s.ws);
    expect((await Promise.all(pending)).every((r) => r.status === 200)).toBe(true);
    expect(relay.registry.get(s.routeId)?.open(() => {})).not.toBeNull();
  });
});

describe("flow control", () => {
  it("counts a peer that sends past its window as a violation", () => {
    const granted: number[] = [];
    const receiver = createFlowReceiver((n) => granted.push(n));
    expect(receiver.accept(STREAM_WINDOW_BYTES)).toBe(true);
    expect(receiver.accept(1)).toBe(false);

    const drained = createFlowReceiver((n) => granted.push(n));
    expect(drained.accept(STREAM_WINDOW_BYTES)).toBe(true);
    drained.drained(65536);
    expect(drained.accept(65536)).toBe(true);
    expect(granted).toEqual([65536]);
  });

  it("refuses credit beyond the window and a malformed grant", () => {
    const sender = createFlowSender(() => {}, { pause() {}, resume() {} });
    expect(() => sender.grant(1)).toThrow(FlowError);
    for (const bad of ["{", "{}", '{"credit":0}', '{"credit":-5}', '{"credit":1.5}', '{"credit":"9"}']) {
      expect(() => parseCredit(Buffer.from(bad))).toThrow(FlowError);
    }
    expect(parseCredit(encodeCredit(7))).toBe(7);
  });
});
