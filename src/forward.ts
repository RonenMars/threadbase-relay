import { createHash, randomBytes } from "crypto";
import type http from "http";
import { createFlowReceiver, createFlowSender, encodeCredit, FlowError, parseCredit } from "./flow";
import { FRAME_TYPES } from "./frames";
import type { Tunnel } from "./registry";
import type { RelayLog } from "./relay";

// Forwards one client HTTP request down a streamer's tunnel and its response
// back. The relay reads the request line and an allowlist of headers; bodies in
// both directions are opaque bytes it never parses, caches or rewrites.

/** Relay-originated refusals are marked so a client never mistakes one for the streamer's. */
export function refuse(res: http.ServerResponse, status: number, code: string, error: string): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-tb-relay-error": "1",
  });
  res.end(JSON.stringify({ error, code }));
}

const FORWARDED_HEADERS = new Set(["content-type", "content-length", "accept", "if-none-match", "etag", "cache-control"]);
export const forwarded = (name: string) => name.startsWith("x-tb-") || FORWARDED_HEADERS.has(name);

/** The two handshakes: the only requests that are not sealed under a context. */
const HANDSHAKE_PATHS = new Set(["/api/e2ee/open", "/api/pair/exchange"]);

// The streamer's largest sealed upload record, plus room for its framing. The
// streamer enforces the real limit; this only stops a body with no end.
const MAX_REQUEST_BODY_BYTES = 64 * 1024 * 1024 + 64 * 1024;
const STREAM_IDLE_TIMEOUT_MS = 60_000;

// The streamer rate-limits on this instead of an address it cannot see. Salted
// per process, so it is not an IP and does not survive a restart.
//
// A forwarding header is whatever the client typed unless a proxy we run behind
// replaced it, so one is read only on a host known to do that: Fly's proxy sets
// `fly-client-ip` and Vercel sets `x-real-ip` to the address the connection came
// from. Anywhere else a client could mint a fresh bucket per request by
// changing it. On those hosts the socket address is the proxy's, which would
// put every client in one bucket instead.
const TAG_SALT = randomBytes(16);
export function clientTag(req: http.IncomingMessage): string {
  const proxied = process.env.FLY_APP_NAME
    ? req.headers["fly-client-ip"]
    : process.env.VERCEL
      ? req.headers["x-real-ip"]
      : undefined;
  const ip = (typeof proxied === "string" && proxied) || req.socket.remoteAddress || "";
  return createHash("sha256").update(TAG_SALT).update(ip).digest("base64url").slice(0, 16);
}

/**
 * Only end-to-end-encrypted traffic is carried. The streamer enforces this too
 * (it is the authority); refusing here keeps a credential a confused client
 * sent in the clear from ever being written to the tunnel.
 */
export function isCarried(req: http.IncomingMessage, target: string): boolean {
  if (carriesCredential(req, target)) return false;
  if (req.headers["x-tb-ctx"] !== undefined) return true;
  return req.method === "POST" && HANDSHAKE_PATHS.has(target.split("?", 1)[0]);
}

/** A long-term credential in the clear: an `Authorization` header or a `?key=`. */
export function carriesCredential(req: http.IncomingMessage, target: string): boolean {
  const q = target.indexOf("?");
  return (
    req.headers.authorization !== undefined || (q !== -1 && new URLSearchParams(target.slice(q + 1)).has("key"))
  );
}

export function forwardHttp(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tunnel: Tunnel,
  target: string,
  log: RelayLog,
  /** Charges bytes to the route's quota; false once it is spent. */
  meter: (bytes: number) => boolean = () => true,
): void {
  if (Number(req.headers["content-length"] ?? 0) > MAX_REQUEST_BODY_BYTES) {
    refuse(res, 400, "RELAY_UNSUPPORTED_REQUEST", "Request body too large");
    return;
  }

  let done = false;
  let idle: NodeJS.Timeout;
  const finish = () => {
    done = true;
    clearTimeout(idle);
    stream?.release();
  };
  const fail = (status: number, code: string, error: string) => {
    if (done) return;
    finish();
    if (res.headersSent) res.destroy();
    else refuse(res, status, code, error);
  };
  const touch = () => {
    clearTimeout(idle);
    idle = setTimeout(() => {
      stream?.send(FRAME_TYPES.RESET);
      fail(504, "RELAY_TIMEOUT", "Streamer did not answer in time");
    }, STREAM_IDLE_TIMEOUT_MS);
  };

  const stream = tunnel.open((frame) => {
    if (done) return;
    touch();
    if (frame.type === FRAME_TYPES.HEAD) {
      if (res.headersSent) return;
      try {
        const head = JSON.parse(frame.payload.toString("utf-8")) as { status?: unknown; headers?: unknown };
        const status = Number(head.status);
        if (!Number.isInteger(status) || status < 200 || status > 599) throw new Error("status");
        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries((head.headers ?? {}) as Record<string, unknown>)) {
          if (forwarded(name.toLowerCase()) && typeof value === "string") headers[name.toLowerCase()] = value;
        }
        res.writeHead(status, headers);
      } catch {
        stream?.send(FRAME_TYPES.RESET);
        fail(502, "RELAY_STREAM_RESET", "Streamer sent a malformed response");
      }
    } else if (frame.type === FRAME_TYPES.DATA) {
      const bytes = frame.payload.length;
      if (!meter(bytes)) {
        stream?.send(FRAME_TYPES.RESET);
        return fail(429, "RELAY_RATE_LIMITED", "This streamer has used its relay quota for today");
      }
      if (!res.headersSent || !inbound.accept(bytes)) {
        stream?.send(FRAME_TYPES.RESET);
        return fail(502, "RELAY_STREAM_RESET", "Streamer broke the stream protocol");
      }
      // Credit goes back only once the client has taken the bytes, so a slow
      // phone stalls the streamer instead of filling this process.
      res.write(frame.payload, (err) => {
        if (!err && !done) inbound.drained(bytes);
      });
    } else if (frame.type === FRAME_TYPES.WINDOW) {
      try {
        outbound.grant(parseCredit(frame.payload));
      } catch (err) {
        if (!(err instanceof FlowError)) throw err;
        stream?.send(FRAME_TYPES.RESET);
        fail(502, "RELAY_STREAM_RESET", "Streamer broke the stream protocol");
      }
    } else if (frame.type === FRAME_TYPES.END) {
      if (!res.headersSent) return fail(502, "RELAY_STREAM_RESET", "Streamer closed the stream");
      finish();
      res.end();
    } else if (frame.type === FRAME_TYPES.RESET) {
      fail(502, "RELAY_STREAM_RESET", "Streamer closed the stream");
    }
  });
  if (!stream) {
    refuse(res, 503, "RELAY_OVERLOADED", "Too many concurrent requests for this streamer");
    return;
  }
  touch();
  const inbound = createFlowReceiver((credit) => stream.send(FRAME_TYPES.WINDOW, encodeCredit(credit)));
  const outbound = createFlowSender((payload) => {
    if (done || stream.send(FRAME_TYPES.DATA, payload)) return;
    fail(503, "RELAY_OVERLOADED", "Streamer is not keeping up");
  }, req);

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (forwarded(name) && typeof value === "string") headers[name] = value;
  }
  stream.send(
    FRAME_TYPES.OPEN,
    Buffer.from(JSON.stringify({ kind: "http", method: req.method, target, headers, clientTag: clientTag(req) })),
  );

  let received = 0;
  req.on("data", (chunk: Buffer) => {
    if (done) return;
    received += chunk.length;
    if (received > MAX_REQUEST_BODY_BYTES) {
      stream.send(FRAME_TYPES.RESET);
      fail(400, "RELAY_UNSUPPORTED_REQUEST", "Request body too large");
      return;
    }
    touch();
    if (!meter(chunk.length)) {
      stream.send(FRAME_TYPES.RESET);
      fail(429, "RELAY_RATE_LIMITED", "This streamer has used its relay quota for today");
      return;
    }
    outbound.write(chunk);
  });
  req.on("end", () =>
    outbound.end(() => {
      if (!done) stream.send(FRAME_TYPES.END);
    }),
  );
  // The client went away before the response finished: tell the streamer to stop.
  res.on("close", () => {
    if (done) return;
    stream.send(FRAME_TYPES.RESET);
    finish();
  });

  log("stream.opened", { tunnelId: tunnel.id });
}
