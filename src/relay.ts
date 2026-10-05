import { randomUUID } from "crypto";
import http from "http";
import { type RawData, WebSocket, WebSocketServer } from "ws";
import { decodeFrame, FrameError, MAX_FRAME_BYTES, MAX_FRAME_PAYLOAD_BYTES } from "./frames";
import type { KeyPair } from "./noise/noise";
import { RouteRegistry, type Tunnel } from "./registry";
import { type AcceptedTunnel, acceptTunnel, UnsupportedProtocolError } from "./tunnel-auth";

export const TUNNEL_PATH = "/tunnel";
export const ROUTE_PREFIX = "/r/";

export const CLOSE_MALFORMED = 4400;
export const CLOSE_AUTH_FAILED = 4401;
export const CLOSE_UNSUPPORTED_PROTOCOL = 4406;
export const CLOSE_HANDSHAKE_TIMEOUT = 4408;

export const TUNNEL_LIMITS = {
  framePayloadBytes: MAX_FRAME_PAYLOAD_BYTES,
  streams: 64,
  streamWindowBytes: 256 * 1024,
};

/** Fields are identifiers and counters only. Never a path, header or payload. */
export type RelayLog = (event: string, fields?: Record<string, string | number>) => void;

export interface RelayOptions {
  relayKeyPair: KeyPair;
  version?: string;
  handshakeTimeoutMs?: number;
  log?: RelayLog;
}

export interface Relay {
  server: http.Server;
  registry: RouteRegistry;
}

/** Relay-originated refusals are marked so a client never mistakes one for the streamer's. */
function refuse(res: http.ServerResponse, status: number, code: string, error: string): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-tb-relay-error": "1",
  });
  res.end(JSON.stringify({ error, code }));
}

// A pseudonymous handle for logs: enough to correlate, not enough to dial.
const routeTag = (routeId: string) => routeId.slice(0, 8);

export function createRelay(options: RelayOptions): Relay {
  const log = options.log ?? (() => {});
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? 10_000;
  const registry = new RouteRegistry();

  const server = http.createServer((req, res) => {
    const path = (req.url ?? "/").split("?", 1)[0];
    if (req.method === "GET" && path === "/healthz") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ ok: true, version: options.version ?? "dev" }));
      return;
    }
    // Client routing lands in a later phase. Until then every route answers the
    // way an offline one will, which is also how an unknown one must answer.
    if (path.startsWith(ROUTE_PREFIX)) {
      refuse(res, 503, "RELAY_STREAMER_OFFLINE", "Streamer is not connected to the relay");
      return;
    }
    refuse(res, 400, "RELAY_UNSUPPORTED_REQUEST", "Unsupported request");
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

  server.on("upgrade", (req, socket, head) => {
    if ((req.url ?? "").split("?", 1)[0] !== TUNNEL_PATH) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => serveTunnel(ws));
  });

  function serveTunnel(ws: WebSocket): void {
    const tunnelId = randomUUID();
    let accepted: AcceptedTunnel | null = null;
    let tunnel: Tunnel | null = null;

    const deadline = setTimeout(() => ws.close(CLOSE_HANDSHAKE_TIMEOUT, "handshake timeout"), handshakeTimeoutMs);

    ws.on("message", (data: RawData, isBinary: boolean) => {
      const bytes = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer);

      if (tunnel) {
        try {
          if (!isBinary) throw new FrameError("Text frame on tunnel");
          // No streams exist yet, so a valid frame has nowhere to go and is dropped.
          decodeFrame(bytes);
        } catch {
          log("tunnel.malformed_frame", { tunnelId });
          ws.close(CLOSE_MALFORMED, "malformed frame");
        }
        return;
      }

      if (!accepted) {
        try {
          accepted = acceptTunnel({
            relayKeyPair: options.relayKeyPair,
            message1: bytes,
            tunnelId,
            limits: TUNNEL_LIMITS,
          });
        } catch (err) {
          const unsupported = err instanceof UnsupportedProtocolError;
          log(unsupported ? "tunnel.unsupported_protocol" : "tunnel.auth_failed", { tunnelId });
          ws.close(
            unsupported ? CLOSE_UNSUPPORTED_PROTOCOL : CLOSE_AUTH_FAILED,
            unsupported ? "unsupported protocol" : "authentication failed",
          );
          return;
        }
        ws.send(accepted.message2);
        return;
      }

      if (!accepted.confirm(bytes)) {
        log("tunnel.auth_failed", { tunnelId });
        ws.close(CLOSE_AUTH_FAILED, "authentication failed");
        return;
      }
      clearTimeout(deadline);
      tunnel = { id: tunnelId, routeId: accepted.routeId, close: (code, reason) => ws.close(code, reason) };
      registry.attach(tunnel);
      log("tunnel.attached", { tunnelId, route: routeTag(tunnel.routeId) });
    });

    ws.on("close", (code) => {
      clearTimeout(deadline);
      if (!tunnel) return;
      registry.detach(tunnel);
      log("tunnel.closed", { tunnelId, route: routeTag(tunnel.routeId), code });
    });
    ws.on("error", () => ws.terminate());
  }

  return { server, registry };
}
