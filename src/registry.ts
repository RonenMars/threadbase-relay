// The route table: which authenticated tunnel currently serves a route id.
//
// A logical stream belongs to exactly one tunnel object and never moves. When a
// streamer reconnects, the new tunnel replaces the old one and the old one is
// closed, so nothing addressed to a route can reach a stale connection.

export interface Tunnel {
  readonly id: string;
  readonly routeId: string;
  close(code: number, reason: string): void;
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
