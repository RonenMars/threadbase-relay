import type { AddressInfo } from "net";
import { WebSocket } from "ws";
import { encodeCredit } from "../src/flow";
import { decodeFrame, encodeFrame, FRAME_TYPES } from "../src/frames";
import { renderMetrics } from "../src/metrics";
import { generateKeyPair } from "../src/noise/noise";
import { createRelay, type Relay } from "../src/relay";
import { completeTunnel, initiateTunnel, routeIdFromStreamerKey } from "../src/tunnel-auth";

const relayKeyPair = generateKeyPair();
let relay: Relay;
let base: string;
const sockets: WebSocket[] = [];
const logged: { event: string; fields: Record<string, string | number> }[] = [];

beforeEach(async () => {
  logged.length = 0;
  relay = createRelay({ relayKeyPair, log: (event, fields = {}) => logged.push({ event, fields }) });
  await new Promise<void>((resolve) => relay.server.listen(0, "127.0.0.1", resolve));
  base = `127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.terminate();
  relay.server.closeAllConnections();
  await new Promise((resolve) => relay.server.close(resolve));
});

/** One series' value from Prometheus text; 0 when the series has not appeared yet. */
const value = (text: string, series: string) =>
  Number(
    text
      .split("\n")
      .find((line) => line.startsWith(`${series} `))
      ?.split(" ")[1] ?? 0,
  );

async function echoStreamer() {
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
  ws.on("message", (data) => {
    const frame = decodeFrame(data as Buffer);
    if (frame.type === FRAME_TYPES.DATA) {
      ws.send(encodeFrame(FRAME_TYPES.WINDOW, frame.streamId, encodeCredit(frame.payload.length)));
    }
    if (frame.type !== FRAME_TYPES.END) return;
    ws.send(encodeFrame(FRAME_TYPES.HEAD, frame.streamId, Buffer.from(JSON.stringify({ status: 200, headers: {} }))));
    ws.send(encodeFrame(FRAME_TYPES.DATA, frame.streamId, Buffer.from("ciphertext")));
    ws.send(encodeFrame(FRAME_TYPES.END, frame.streamId));
  });
  return routeId;
}

describe("renderMetrics", () => {
  it("renders labelled counters and gauges one series per line", () => {
    const text = renderMetrics({ relay_example_gauge: 3 });
    expect(text.endsWith("relay_example_gauge 3\n")).toBe(true);
    for (const line of text.trimEnd().split("\n")) expect(line).toMatch(/^[a-z_]+(\{[a-z]+="[^"]*"\})? \d+$/);
  });
});

describe("relay metrics", () => {
  it("counts streams, bytes, refusals and events, with gauges for what is open", async () => {
    const before = relay.metrics();
    const routeId = await echoStreamer();
    const body = Buffer.alloc(500, 1);
    const res = await fetch(`http://${base}/r/${routeId}/api/x`, { method: "POST", headers: { "x-tb-ctx": "c" }, body });
    expect(await res.text()).toBe("ciphertext");
    expect((await fetch(`http://${base}/r/${routeId}/api/info`)).status).toBe(400);
    const after = relay.metrics();

    const delta = (series: string) => value(after, series) - value(before, series);
    expect(delta('relay_streams_opened_total{kind="http"}')).toBe(1);
    expect(delta("relay_bytes_total")).toBe(500 + "ciphertext".length);
    expect(delta('relay_refused_total{code="RELAY_UNSUPPORTED_REQUEST"}')).toBe(1);
    expect(delta('relay_events_total{event="tunnel.attached"}')).toBe(1);
    expect(value(after, "relay_tunnels")).toBe(1);
    expect(value(after, "relay_requests_in_flight")).toBe(0);
  });

  it("names no route, tunnel or address in a scrape, and logs no line per request", async () => {
    const routeId = await echoStreamer();
    await fetch(`http://${base}/r/${routeId}/api/x`, { headers: { "x-tb-ctx": "c" } });
    const text = relay.metrics();
    const attached = logged.find((l) => l.event === "tunnel.attached");

    // Positive control: the log does carry the pseudonymous handles, so their
    // absence from the scrape below is not a harness that never saw them.
    expect(attached?.fields.route).toBe(routeId.slice(0, 8));
    expect(text).not.toContain(routeId.slice(0, 8));
    expect(text).not.toContain(String(attached?.fields.tunnelId));
    expect(text).not.toContain("127.0.0.1");

    // Nothing after the attach: the request itself left no line.
    expect(logged.slice(logged.indexOf(attached as (typeof logged)[number]) + 1)).toEqual([]);
    for (const { fields } of logged) expect(Object.values(fields)).not.toContain(routeId);
  });
});
