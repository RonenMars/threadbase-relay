// Counts events per key in fixed windows. The whole table is dropped at each
// window boundary, so memory is bounded by the keys seen in one window.
// ponytail: a fixed window lets a key burst to 2x the limit across a boundary;
// switch to a sliding window if that ever matters.

export interface RateLimiter {
  /** 0 when the event is allowed, otherwise the seconds until the key may try again. */
  take(key: string): number;
}

export function createRateLimiter(limit: number, windowMs: number, now: () => number = Date.now): RateLimiter {
  let windowStart = now();
  let counts = new Map<string, number>();
  return {
    take(key) {
      const t = now();
      if (t - windowStart >= windowMs) {
        windowStart = t;
        counts = new Map();
      }
      const n = (counts.get(key) ?? 0) + 1;
      counts.set(key, n);
      return n > limit ? Math.max(1, Math.ceil((windowStart + windowMs - t) / 1000)) : 0;
    },
  };
}
