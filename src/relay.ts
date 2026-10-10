import { randomUUID } from "crypto";
import http from "http";
import { type RawData, WebSocket, WebSocketServer } from "ws";
import { STREAM_WINDOW_BYTES } from "./flow";
import { clientTag, forwardHttp, isCarried, refuse } from "./forward";
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
import { createConcurrencyLimit, createRateLimiter } from "./rate-limit";
import { RouteRegistry, type Tunnel } from "./registry";
import { type AcceptedTunnel, acceptTunnel, UnsupportedProtocolError } from "./tunnel-auth";
import { count, renderMetrics } from "./metrics";
import { closeClientSockets, forwardSocket, isCarriedSocket, openClientSockets, refuseUpgrade } from "./ws-forward";

export const TUNNEL_PATH = "/tunnel";
export const ROUTE_PREFIX = "/r/";

export const CLOSE_MALFORMED = 4400;
export const CLOSE_AUTH_FAILED = 4401;
export const CLOSE_UNSUPPORTED_PROTOCOL = 4406;
export const CLOSE_HANDSHAKE_TIMEOUT = 4408;
export const CLOSE_RATE_LIMITED = 4429;
/** WebSocket "service restart": the peer should come back, not give up. */
export const CLOSE_RESTARTING = 1012;

/** Per minute. Clients and tunnel dials are keyed by the client tag, replacements by route. */
export const RATE_LIMITS = {
  /** Relayed requests and sockets from one client address, across all routes. */
  clientRequests: 600,
  /** Tunnel dials from one address: each costs the relay a Diffie-Hellman. */
  tunnelHandshakes: 30,
  /** Times a route's tunnel may be replaced, so two holders of one key cannot flap it. */
  tunnelReplacements: 10,
  /**
   * Requests and sockets one client address holds open at once. Generous
   * because a carrier NAT puts many phones behind one address.
   */
  clientConnections: 256,
  /** Tunnels one address holds open at once; an office NAT may hold several streamers. */
  tunnelConnections: 32,
  /**
   * Body bytes one route carries per day, both directions. Admission is open,
   * so this is what bounds the bandwidth any one keypair can cost.
   * ponytail: in memory, so a restart resets it; persist it if one relay
   * process stops being the whole deployment.
   */
  routeBytesPerDay: 10 * 1024 ** 3,
};

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
  rateLimits?: Partial<typeof RATE_LIMITS>;
}

export interface Relay {
  server: http.Server;
  registry: RouteRegistry;
  /**
   * Stop taking work, let requests in flight finish for up to `deadlineMs`,
   * then close every tunnel and socket with CLOSE_RESTARTING.
   */
  drain(deadlineMs: number): Promise<void>;
  /** Counters and gauges as Prometheus text. */
  metrics(): string;
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
  const emit = options.log ?? (() => {});
  // Every logged event is also counted, so a metric exists for each one.
  const log: RelayLog = (event, fields) => {
    count("relay_events_total", ["event", event]);
    emit(event, fields);
  };
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? 10_000;
  const registry = new RouteRegistry();
  const limits = { ...RATE_LIMITS, ...options.rateLimits };
  const clients = createRateLimiter(limits.clientRequests, 60_000);
  const dials = createRateLimiter(limits.tunnelHandshakes, 60_000);
  const replacements = createRateLimiter(limits.tunnelReplacements, 60_000);
  const clientConnections = createConcurrencyLimit(limits.clientConnections);
  const tunnelConnections = createConcurrencyLimit(limits.tunnelConnections);
  const routeBytes = createRateLimiter(limits.routeBytesPerDay, 86_400_000);
  const meter = (routeId: string) => (bytes: number) => {
    count("relay_bytes_total", undefined, bytes);
    return routeBytes.take(routeId, bytes) === 0;
  };
  let draining = false;
  let inFlight = 0;

  const server = http.createServer((req, res) => {
    // Answering instead of closing the listener: Fly's proxy reaches us over
    // connections it keeps open, so only an answer turns its requests away, and
    // a failing /healthz is what tells it this machine is going.
    if (draining) {
      res.setHeader("connection", "close");
      refuse(res, 503, "RELAY_RESTARTING", "Relay is restarting");
      return;
    }
    inFlight++;
    res.on("close", () => inFlight--);
    const path = (req.url ?? "/").split("?", 1)[0];
    if (req.method === "GET" && path === "/healthz") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ ok: true, version: options.version ?? "dev" }));
      return;
    }
    const route = parseRoute(req.url ?? "/");
    if (route) {
      const { routeId, target } = route;
      // Counted before anything else, so probing for routes is limited too.
      const tag = clientTag(req);
      const wait = clients.take(tag);
      if (wait) {
        log("client.rate_limited");
        res.setHeader("retry-after", String(wait));
        refuse(res, 429, "RELAY_RATE_LIMITED", "Too many requests");
        return;
      }
      if (!clientConnections.acquire(tag)) {
        log("client.connection_limited");
        refuse(res, 503, "RELAY_OVERLOADED", "Too many open requests");
        return;
      }
      res.on("close", () => clientConnections.release(tag));
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
      const quotaWait = routeBytes.take(routeId, 0);
      if (quotaWait) {
        log("route.quota_exceeded", { route: routeTag(routeId) });
        res.setHeader("retry-after", String(quotaWait));
        refuse(res, 429, "RELAY_RATE_LIMITED", "This streamer has used its relay quota for today");
        return;
      }
      forwardHttp(req, res, tunnel, target, meter(routeId));
      return;
    }
    refuse(res, 400, "RELAY_UNSUPPORTED_REQUEST", "Unsupported request");
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

  server.on("upgrade", (req, socket, head) => {
    // A peer that resets mid-upgrade must not take the process down.
    socket.on("error", () => {});
    if (draining) {
      refuseUpgrade(socket, 503);
      return;
    }
    const url = req.url ?? "/";
    if (url.split("?", 1)[0] === TUNNEL_PATH) {
      const tag = clientTag(req);
      const wait = dials.take(tag);
      if (wait) {
        log("tunnel.rate_limited");
        refuseUpgrade(socket, 429, wait);
        return;
      }
      if (!tunnelConnections.acquire(tag)) {
        log("tunnel.connection_limited");
        refuseUpgrade(socket, 503);
        return;
      }
      socket.on("close", () => tunnelConnections.release(tag));
      wss.handleUpgrade(req, socket, head, (ws) => serveTunnel(ws));
      return;
    }
    const route = parseRoute(url);
    const tag = clientTag(req);
    const wait = route ? clients.take(tag) : 0;
    if (wait) {
      log("client.rate_limited");
      refuseUpgrade(socket, 429, wait);
      return;
    }
    if (route && !clientConnections.acquire(tag)) {
      log("client.connection_limited");
      refuseUpgrade(socket, 503);
      return;
    }
    if (route) socket.on("close", () => clientConnections.release(tag));
    // Decided before the lookup, as for HTTP: an unsealed probe learns nothing.
    if (!route || !isCarriedSocket(req, route.target)) {
      refuseUpgrade(socket, 400);
      return;
    }
    const quotaWait = routeBytes.take(route.routeId, 0);
    if (quotaWait) {
      log("route.quota_exceeded", { route: routeTag(route.routeId) });
      refuseUpgrade(socket, 429, quotaWait);
      return;
    }
    forwardSocket(req, socket, head, registry.get(route.routeId), route.target, meter(route.routeId));
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
      // The serving tunnel stays; the newcomer waits out the window.
      if (registry.get(accepted.routeId) && replacements.take(accepted.routeId)) {
        log("tunnel.replacement_rate_limited", { tunnelId, route: routeTag(accepted.routeId) });
        ws.close(CLOSE_RATE_LIMITED, "replaced too often");
        return;
      }
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

  const settle = async (done: () => boolean, deadline: number) => {
    while (!done() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
  };

  async function drain(deadlineMs: number): Promise<void> {
    draining = true;
    log("relay.draining", { inFlight, tunnels: registry.size });
    closeClientSockets(CLOSE_RESTARTING, "relay restarting");
    // Requests ride on tunnels, so the tunnels stay up until they finish.
    await settle(() => inFlight === 0, Date.now() + deadlineMs);
    for (const ws of wss.clients) ws.close(CLOSE_RESTARTING, "relay restarting");
    // Long enough for the close frames to leave, not for a peer that never answers.
    await settle(() => wss.clients.size === 0, Date.now() + 1000);
    log("relay.drained", { inFlight });
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }

  const metrics = () =>
    renderMetrics({
      relay_tunnels: registry.size,
      relay_requests_in_flight: inFlight,
      relay_client_sockets: openClientSockets(),
    });

  return { server, registry, drain, metrics };
}
