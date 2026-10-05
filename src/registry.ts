// The route table: which authenticated tunnel currently serves a route id.
//
// A logical stream belongs to exactly one tunnel object and never moves. When a
// streamer reconnects, the new tunnel replaces the old one and the old one is
// closed, so nothing addressed to a route can reach a stale connection.

import type { Frame, FrameType } from "./frames";

/** One logical stream. Its id is allocated by the relay and means nothing outside its tunnel. */
export interface Stream {
  send(type: FrameType, payload?: Buffer): void;
  /** Forget the stream. Frames that still arrive for it are dropped. */
  release(): void;
}

export interface Tunnel {
  readonly id: string;
  readonly routeId: string;
  close(code: number, reason: string): void;
  /**
   * Open a stream on THIS tunnel, or null at the stream limit. When the tunnel
   * dies the handler receives a RESET, so a stream never outlives its tunnel
   * and is never moved to the one that replaces it.
   */
  open(onFrame: (frame: Frame) => void): Stream | null;
}

export const CLOSE_REPLACED = 4409;

export class RouteRegistry {
  readonly #tunnels = new Map<string, Tunnel>();

  get size(): number {
    return this.#tunnels.size;
  }

  get(routeId: string): Tunnel | undefined {
    return this.#tunnels.get(routeId);
  }

  attach(tunnel: Tunnel): void {
    const previous = this.#tunnels.get(tunnel.routeId);
    this.#tunnels.set(tunnel.routeId, tunnel);
    previous?.close(CLOSE_REPLACED, "replaced");
  }

  /** A replaced tunnel closing late must not remove its successor. */
  detach(tunnel: Tunnel): void {
    if (this.#tunnels.get(tunnel.routeId) === tunnel) this.#tunnels.delete(tunnel.routeId);
  }
}
