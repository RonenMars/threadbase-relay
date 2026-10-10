import http from "http";
import type { Duplex } from "stream";
import { type RawData, type WebSocket, WebSocketServer } from "ws";
import { createFlowReceiver, createFlowSender, encodeCredit, FlowError, parseCredit } from "./flow";
import { FRAME_TYPES, MAX_FRAME_PAYLOAD_BYTES } from "./frames";
import { carriesCredential, clientTag, forwarded } from "./forward";
import type { Tunnel } from "./registry";
import type { RelayLog } from "./relay";

// Carries one client WebSocket down a streamer's tunnel as a logical stream.
// The upgrade is completed only once the streamer has accepted it, so the
// streamer stays the authority on who gets a socket. Messages are opaque: the
// relay moves them, split to fit a frame, and never reads one.

/** The first byte of a WebSocket DATA payload. Set when more of the same message follows. */
export const MORE = 1;

const E2EE_SUBPROTOCOL = "threadbase-e2ee-v1";
/** "Try again later": every relay-originated close, with the relay code as its reason. */
const CLOSE_TRY_AGAIN = 1013;
// Sockets are long-lived, so they are held well under the tunnel's stream
// limit: a route's open sockets can never crowd out its HTTP requests.
const MAX_SOCKETS_PER_TUNNEL = 16;
const ACCEPT_DEADLINE_MS = 10_000;
// A phone that sleeps sends no FIN. Pinging finds the dead socket and frees
// its stream; it also keeps an idle socket open through the host's proxy.
const PING_INTERVAL_MS = 30_000;
// The streamer enforces its own, smaller, bound on a client message. This only
// stops one message from growing without end in this process.
const MAX_MESSAGE_BYTES = 1024 * 1024;

const selected = new WeakMap<http.IncomingMessage, string>();
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_MESSAGE_BYTES,
  // Only what the streamer selected, never the first offer: a browser presents
  // its ticket as an offered subprotocol, and echoing it would leak it.
  handleProtocols: (_offered, req) => selected.get(req) ?? false,
});
const socketCounts = new WeakMap<Tunnel, number>();

const offeredProtocols = (req: http.IncomingMessage) =>
  String(req.headers["sec-websocket-protocol"] ?? "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);

/** Refuse an upgrade without completing it. */
export function refuseUpgrade(socket: Duplex, status: number, retryAfterSeconds?: number): void {
  const retry = retryAfterSeconds ? `retry-after: ${retryAfterSeconds}\r\n` : "";
  socket.end(
    `HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? "Refused"}\r\nconnection: close\r\n${retry}content-length: 0\r\n\r\n`,
  );
}

/** Only a socket that presents an end-to-end-encryption ticket is carried. */
export function isCarriedSocket(req: http.IncomingMessage, target: string): boolean {
  if (target.split("?", 1)[0] !== "/ws" || carriesCredential(req, target)) return false;
  return typeof req.headers["x-tb-ticket"] === "string" || offeredProtocols(req).includes(E2EE_SUBPROTOCOL);
}

function closeWith(ws: WebSocket, code: unknown, reason: unknown): void {
  try {
    ws.close(code as number, typeof reason === "string" ? reason : undefined);
  } catch {
    // Not a code that may be sent (1005, 1006, out of range).
    ws.close();
  }
}

export function forwardSocket(
  req: http.IncomingMessage,
  socket: Duplex,
  upgradeHead: Buffer,
  tunnel: Tunnel | undefined,
  target: string,
  log: RelayLog,
): void {
  const protocols = offeredProtocols(req);
  let ws: WebSocket | null = null;
  let done = false;
  let deadline: NodeJS.Timeout | undefined;
  let ping: NodeJS.Timeout | undefined;

  // A relay refusal completes the upgrade first, because a close code and
  // reason are the only failure detail a WebSocket client can read.
  const refuse = (code: string) => {
    if (protocols.includes(E2EE_SUBPROTOCOL)) selected.set(req, E2EE_SUBPROTOCOL);
    wss.handleUpgrade(req, socket, upgradeHead, (client) => client.close(CLOSE_TRY_AGAIN, code));
  };

  // An unknown route answers exactly as an offline one.
  if (!tunnel) return refuse("RELAY_STREAMER_OFFLINE");
  const count = socketCounts.get(tunnel) ?? 0;
  if (count >= MAX_SOCKETS_PER_TUNNEL) return refuse("RELAY_OVERLOADED");

  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(deadline);
    clearInterval(ping);
    stream?.release();
    socketCounts.set(tunnel, (socketCounts.get(tunnel) ?? 1) - 1);
  };
  const fail = (code: string) => {
    if (done) return;
    finish();
    if (ws) ws.close(CLOSE_TRY_AGAIN, code);
    else refuse(code);
  };
  const abort = (code: string) => {
    stream?.send(FRAME_TYPES.RESET);
    fail(code);
  };

  const attach = (client: WebSocket) => {
    ws = client;
    let alive = true;
    client.on("pong", () => {
      alive = true;
    });
    ping = setInterval(() => {
      if (!alive) return client.terminate();
      alive = false;
      client.ping();
    }, PING_INTERVAL_MS);
    client.on("message", (data: RawData, isBinary: boolean) => {
      if (done) return;
      if (!isBinary) {
        // A sealed socket carries one record per binary message and nothing else.
        stream?.send(FRAME_TYPES.RESET);
        finish();
        client.close(1003, "binary only");
        return;
      }
      outbound.write(Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer));
    });
    client.on("close", (code, reason) => {
      clearInterval(ping);
      // ponytail: what the client sent before closing still waits for credit,
      // so a streamer that never grants any keeps this entry until its tunnel
      // closes. It only spends its own socket limit; add a deadline if a
      // stream must be freed sooner.
      outbound.end(() => {
        if (done) return;
        stream?.send(FRAME_TYPES.END, Buffer.from(JSON.stringify({ code, reason: reason.toString("utf-8") })));
        finish();
      });
    });
    client.on("error", () => client.terminate());
  };

  const stream = tunnel.open((frame) => {
    if (done) return;
    if (frame.type === FRAME_TYPES.HEAD) {
      if (ws) return;
      let head: { accepted?: unknown; protocol?: unknown; status?: unknown };
      try {
        head = JSON.parse(frame.payload.toString("utf-8"));
      } catch {
        head = {};
      }
      if (head.accepted !== true) {
        // The streamer refused the upgrade: answer as it would have directly.
        const status = Number(head.status);
        finish();
        refuseUpgrade(socket, Number.isInteger(status) && status >= 400 && status <= 599 ? status : 502);
        return;
      }
      if (typeof head.protocol === "string") {
        if (!protocols.includes(head.protocol)) return abort("RELAY_STREAM_RESET");
        selected.set(req, head.protocol);
      }
      clearTimeout(deadline);
      wss.handleUpgrade(req, socket, upgradeHead, attach);
    } else if (frame.type === FRAME_TYPES.DATA) {
      const piece = frame.payload.subarray(1);
      if (!ws || frame.payload.length === 0 || !inbound.accept(piece.length)) return abort("RELAY_STREAM_RESET");
      // Credit goes back only once the client has taken the bytes, so a slow
      // phone stalls the streamer's socket instead of filling this process.
      ws.send(piece, { binary: true, fin: (frame.payload[0] & MORE) === 0 }, (err) => {
        if (!err && !done) inbound.drained(piece.length);
      });
    } else if (frame.type === FRAME_TYPES.WINDOW) {
      try {
        outbound.grant(parseCredit(frame.payload));
      } catch (err) {
        if (!(err instanceof FlowError)) throw err;
        abort("RELAY_STREAM_RESET");
      }
    } else if (frame.type === FRAME_TYPES.END) {
      if (!ws) return fail("RELAY_STREAM_RESET");
      let close: { code?: unknown; reason?: unknown };
      try {
        close = JSON.parse(frame.payload.toString("utf-8"));
      } catch {
        close = {};
      }
      finish();
      closeWith(ws, close.code, close.reason);
    } else if (frame.type === FRAME_TYPES.RESET) {
      fail("RELAY_STREAM_RESET");
    }
  });
  if (!stream) return refuse("RELAY_OVERLOADED");
  socketCounts.set(tunnel, count + 1);

  const inbound = createFlowReceiver((credit) => stream.send(FRAME_TYPES.WINDOW, encodeCredit(credit)));
  const outbound = createFlowSender(
    (piece, last) => {
      if (done) return;
      const payload = Buffer.concat([Buffer.from([last ? 0 : MORE]), piece]);
      if (!stream.send(FRAME_TYPES.DATA, payload)) abort("RELAY_OVERLOADED");
    },
    { pause: () => ws?.pause(), resume: () => ws?.resume() },
    MAX_FRAME_PAYLOAD_BYTES - 1,
  );

  deadline = setTimeout(() => abort("RELAY_TIMEOUT"), ACCEPT_DEADLINE_MS);
  // The client gave up before the streamer answered.
  socket.on("close", () => {
    if (ws || done) return;
    stream.send(FRAME_TYPES.RESET);
    finish();
  });

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if ((forwarded(name) || name === "sec-websocket-protocol") && typeof value === "string") headers[name] = value;
  }
  stream.send(
    FRAME_TYPES.OPEN,
    Buffer.from(JSON.stringify({ kind: "ws", method: "GET", target, headers, clientTag: clientTag(req) })),
  );
  log("stream.opened", { tunnelId: tunnel.id, kind: "ws" });
}
