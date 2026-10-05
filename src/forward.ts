import { createHash, randomBytes } from "crypto";
import type http from "http";
import { FRAME_TYPES, MAX_FRAME_PAYLOAD_BYTES } from "./frames";
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
const forwarded = (name: string) => name.startsWith("x-tb-") || FORWARDED_HEADERS.has(name);

/** The two handshakes: the only requests that are not sealed under a context. */
const HANDSHAKE_PATHS = new Set(["/api/e2ee/open", "/api/pair/exchange"]);

// ponytail: fixed cap and no flow control until the generic-HTTP phase; an
// upload needs credit-based windows before this can rise.
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const STREAM_IDLE_TIMEOUT_MS = 60_000;

// The streamer rate-limits on this instead of an address it cannot see. Salted
// per process, so it is not an IP and does not survive a restart.
const TAG_SALT = randomBytes(16);
function clientTag(req: http.IncomingMessage): string {
  const fwd = req.headers["x-forwarded-for"];
  const ip = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(",")[0].trim() || req.socket.remoteAddress || "";
  return createHash("sha256").update(TAG_SALT).update(ip).digest("base64url").slice(0, 16);
}

/**
 * Only end-to-end-encrypted traffic is carried. The streamer enforces this too
 * (it is the authority); refusing here keeps a credential a confused client
 * sent in the clear from ever being written to the tunnel.
 */
export function isCarried(req: http.IncomingMessage, target: string): boolean {
  const q = target.indexOf("?");
  const pathname = q === -1 ? target : target.slice(0, q);
  if (req.headers.authorization !== undefined) return false;
  if (q !== -1 && new URLSearchParams(target.slice(q + 1)).has("key")) return false;
  if (req.headers["x-tb-ctx"] !== undefined) return true;
  return req.method === "POST" && HANDSHAKE_PATHS.has(pathname);
}

export function forwardHttp(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tunnel: Tunnel,
  target: string,
  log: RelayLog,
): void {
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
      if (res.headersSent) res.write(frame.payload);
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
    for (let at = 0; at < chunk.length; at += MAX_FRAME_PAYLOAD_BYTES) {
      stream.send(FRAME_TYPES.DATA, chunk.subarray(at, at + MAX_FRAME_PAYLOAD_BYTES));
    }
  });
  req.on("end", () => {
    if (!done) stream.send(FRAME_TYPES.END);
  });
  // The client went away before the response finished: tell the streamer to stop.
  res.on("close", () => {
    if (done) return;
    stream.send(FRAME_TYPES.RESET);
    finish();
  });

  log("stream.opened", { tunnelId: tunnel.id });
}
