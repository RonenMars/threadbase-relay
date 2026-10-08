import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import { encodeCredit } from "../src/flow";
import { decodeFrame, encodeFrame, type Frame, FRAME_TYPES } from "../src/frames";
import { generateKeyPair } from "../src/noise/noise";
import { CLOSE_RESTARTING, createRelay, type Relay } from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey } from "../src/tunnel-auth";

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
  if (!relay.server.listening) return;
  relay.server.closeAllConnections();
  await new Promise((resolve) => relay.server.close(resolve));
});

const until = async (condition: () => boolean) => {
  for (let i = 0; i < 400 && !condition(); i++) await new Promise((r) => setTimeout(r, 5));
};
const closed = (ws: WebSocket) => new Promise<number>((resolve) => ws.once("close", resolve));

/** A streamer that accepts sockets and holds every HTTP request until `answer` is called. */
async function streamer() {
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
  const held: number[] = [];
  ws.on("message", (data) => {
    const frame: Frame = decodeFrame(data as Buffer);
    if (frame.type === FRAME_TYPES.OPEN && JSON.parse(frame.payload.toString()).kind === "ws") {
      ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify({ accepted: true }))));
    } else if (frame.type === FRAME_TYPES.DATA) {
      ws.send(encodeFrame(FRAME_TYPES.WINDOW, frame.streamId, encodeCredit(frame.payload.length)));
    } else if (frame.type === FRAME_TYPES.END) {
      held.push(frame.streamId);
    }
  });
  const answer = (streamId: number) => {
    ws.send(encodeFrame(FRAME_TYPES.HEAD, streamId, Buffer.from(JSON.stringify({ status: 200, headers: {} }))));
    ws.send(encodeFrame(FRAME_TYPES.DATA, streamId, Buffer.from("ciphertext")));
    ws.send(encodeFrame(FRAME_TYPES.END, streamId));
  };
  return { ws, routeId, held, answer };
}

describe("drain", () => {
  it("finishes a request in flight before closing the tunnel, and closes sockets at once", async () => {
    const s = await streamer();
    const tunnelClosed = closed(s.ws);
    const client = new WebSocket(`ws://${base}/r/${s.routeId}/ws`, { headers: { "x-tb-ticket": "t" } });
    sockets.push(client);
    await new Promise((resolve) => client.once("open", resolve));
    const clientClosed = closed(client);

    const pending = fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: { "x-tb-ctx": "c" } });
    await until(() => s.held.length === 1);

    let drained = false;
    const draining = relay.drain(5_000).then(() => {
      drained = true;
    });

    expect(await clientClosed).toBe(CLOSE_RESTARTING);
    // Turned away while draining, health check included, and marked as the relay's own answer.
    const health = await fetch(`http://${base}/healthz`);
    expect(health.status).toBe(503);
    expect(health.headers.get("x-tb-relay-error")).toBe("1");
    expect((await health.json()).code).toBe("RELAY_RESTARTING");
    const dial = new WebSocket(`ws://${base}/tunnel`);
    sockets.push(dial);
    dial.on("error", () => {});
    expect(await new Promise((resolve) => dial.once("unexpected-response", (_q, r) => resolve(r.statusCode)))).toBe(503);

    // The tunnel carrying the request stays up until the request finishes.
    await new Promise((r) => setTimeout(r, 100));
    expect(s.ws.readyState).toBe(WebSocket.OPEN);
    expect(drained).toBe(false);

    s.answer(s.held[0]);
    const res = await pending;
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ciphertext");

    expect(await tunnelClosed).toBe(CLOSE_RESTARTING);
    await draining;
    expect(relay.server.listening).toBe(false);
  });

  it("gives up on a request that outlives the deadline", async () => {
    const s = await streamer();
    const tunnelClosed = closed(s.ws);
    const pending = fetch(`http://${base}/r/${s.routeId}/api/x`, { headers: { "x-tb-ctx": "c" } }).then(
      (r) => r.status,
      () => "failed",
    );
    await until(() => s.held.length === 1);

    const started = Date.now();
    await relay.drain(200);
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(await tunnelClosed).toBe(CLOSE_RESTARTING);
    // The streamer never answered, so the client sees the stream cut, not a hang.
    expect(await pending).not.toBe(200);
  });
});
