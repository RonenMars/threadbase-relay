// Counts events per key in fixed windows. The whole table is dropped at each
// window boundary, so memory is bounded by the keys seen in one window.
// ponytail: a fixed window lets a key burst to 2x the limit across a boundary;
// switch to a sliding window if that ever matters.

export interface RateLimiter {
  /**
   * Charges `cost` (default 1) to the key. 0 when the key is within its limit,
   * otherwise the seconds until it may try again. A cost of 0 only asks.
   */
  take(key: string, cost?: number): number;
}

export function createRateLimiter(limit: number, windowMs: number, now: () => number = Date.now): RateLimiter {
  let windowStart = now();
  let counts = new Map<string, number>();
  return {
    take(key, cost = 1) {
      const t = now();
      if (t - windowStart >= windowMs) {
        windowStart = t;
        counts = new Map();
      }
      const n = (counts.get(key) ?? 0) + cost;
      counts.set(key, n);
      return n > limit ? Math.max(1, Math.ceil((windowStart + windowMs - t) / 1000)) : 0;
    },
  };
}

/** Caps how many of something one key holds open at once. */
export function createConcurrencyLimit(max: number) {
  const open = new Map<string, number>();
  return {
    acquire(key: string): boolean {
      const n = open.get(key) ?? 0;
      if (n >= max) return false;
      open.set(key, n + 1);
      return true;
    },
    release(key: string): void {
      const n = (open.get(key) ?? 1) - 1;
      if (n > 0) open.set(key, n);
      else open.delete(key);
    },
  };
}
