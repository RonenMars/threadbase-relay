import { randomUUID } from "crypto";
import http from "http";
import { type RawData, WebSocket, WebSocketServer } from "ws";
import { STREAM_WINDOW_BYTES } from "./flow";
import { forwardHttp, isCarried, refuse } from "./forward";
import {
  decodeFrame,
  encodeFrame,
  type Frame,
  FRAME_TYPES,
  FrameError,
  MAX_FRAME_BYTES,
  MAX_FRAME_PAYLOAD_BYTES,
} from "./frames";
import type { KeyPair } from "./noise/noise";
import { RouteRegistry, type Tunnel } from "./registry";
import { type AcceptedTunnel, acceptTunnel, UnsupportedProtocolError } from "./tunnel-auth";
import { forwardSocket, isCarriedSocket, refuseUpgrade } from "./ws-forward";

export const TUNNEL_PATH = "/tunnel";
export const ROUTE_PREFIX = "/r/";

export const CLOSE_MALFORMED = 4400;
export const CLOSE_AUTH_FAILED = 4401;
export const CLOSE_UNSUPPORTED_PROTOCOL = 4406;
export const CLOSE_HANDSHAKE_TIMEOUT = 4408;

export const TUNNEL_LIMITS = {
  framePayloadBytes: MAX_FRAME_PAYLOAD_BYTES,
  streams: 64,
  streamWindowBytes: STREAM_WINDOW_BYTES,
};

/** Unsent bytes a tunnel may hold before new frames for it are refused. */
const MAX_TUNNEL_BUFFERED_BYTES = 8 * 1024 * 1024;

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

/** Split `/r/<routeId>/<target>` into the route and what the streamer is asked for. */
function parseRoute(url: string): { routeId: string; target: string } | null {
  const path = url.split("?", 1)[0];
  if (!path.startsWith(ROUTE_PREFIX)) return null;
  const slash = path.indexOf("/", ROUTE_PREFIX.length);
  return {
    routeId: path.slice(ROUTE_PREFIX.length, slash === -1 ? undefined : slash),
    target: slash === -1 ? "/" : url.slice(slash),
  };
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
    const route = parseRoute(req.url ?? "/");
    if (route) {
      const { routeId, target } = route;
      // Decided before the lookup, so a probe that is not sealed learns nothing
      // about whether the route is attached.
      if (!isCarried(req, target)) {
        refuse(res, 400, "RELAY_UNSUPPORTED_REQUEST", "Only end-to-end-encrypted requests are relayed");
        return;
      }
      const tunnel = registry.get(routeId);
      // An unknown route answers exactly as an offline one: never 404.
      if (!tunnel) {
        refuse(res, 503, "RELAY_STREAMER_OFFLINE", "Streamer is not connected to the relay");
        return;
      }
      forwardHttp(req, res, tunnel, target, log);
      return;
    }
    refuse(res, 400, "RELAY_UNSUPPORTED_REQUEST", "Unsupported request");
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

  server.on("upgrade", (req, socket, head) => {
    // A peer that resets mid-upgrade must not take the process down.
    socket.on("error", () => {});
    const url = req.url ?? "/";
    if (url.split("?", 1)[0] === TUNNEL_PATH) {
      wss.handleUpgrade(req, socket, head, (ws) => serveTunnel(ws));
      return;
    }
    const route = parseRoute(url);
    // Decided before the lookup, as for HTTP: an unsealed probe learns nothing.
    if (!route || !isCarriedSocket(req, route.target)) {
      refuseUpgrade(socket, 400);
      return;
    }
    forwardSocket(req, socket, head, registry.get(route.routeId), route.target, log);
  });

  function serveTunnel(ws: WebSocket): void {
    const tunnelId = randomUUID();
    let accepted: AcceptedTunnel | null = null;
    let tunnel: Tunnel | null = null;
    const streams = new Map<number, (frame: Frame) => void>();
    let nextStreamId = 1;

    const deadline = setTimeout(() => ws.close(CLOSE_HANDSHAKE_TIMEOUT, "handshake timeout"), handshakeTimeoutMs);

    ws.on("message", (data: RawData, isBinary: boolean) => {
      const bytes = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer);

      if (tunnel) {
        try {
          if (!isBinary) throw new FrameError("Text frame on tunnel");
          const frame = decodeFrame(bytes);
          // A frame for a stream that already ended is late, not hostile: dropped.
          streams.get(frame.streamId)?.(frame);
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
      tunnel = {
        id: tunnelId,
        routeId: accepted.routeId,
        close: (code, reason) => ws.close(code, reason),
        open: (onFrame) => {
          if (ws.readyState !== WebSocket.OPEN || streams.size >= TUNNEL_LIMITS.streams) return null;
          const streamId = nextStreamId++;
          streams.set(streamId, onFrame);
          return {
            send: (type, payload) => {
              if (ws.readyState !== WebSocket.OPEN || ws.bufferedAmount > MAX_TUNNEL_BUFFERED_BYTES) return false;
              ws.send(encodeFrame(type, streamId, payload));
              return true;
            },
            release: () => streams.delete(streamId),
          };
        },
      };
      registry.attach(tunnel);
      log("tunnel.attached", { tunnelId, route: routeTag(tunnel.routeId) });
    });

    ws.on("close", (code) => {
      clearTimeout(deadline);
      if (!tunnel) return;
      registry.detach(tunnel);
      for (const [streamId, onFrame] of streams) {
        onFrame({ type: FRAME_TYPES.RESET, streamId, payload: Buffer.alloc(0) });
      }
      streams.clear();
      log("tunnel.closed", { tunnelId, route: routeTag(tunnel.routeId), code });
    });
    ws.on("error", () => ws.terminate());
  }

  return { server, registry };
}
