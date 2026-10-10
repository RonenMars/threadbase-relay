// Process-wide counters, rendered as Prometheus text. Labels come only from
// fixed vocabularies (event names, refusal codes, statuses), never a route,
// tunnel or address, so a scrape shows volumes and never who.

const counters = new Map<string, number>();

export function count(name: string, label?: [string, string], by = 1): void {
  const key = label ? `${name}{${label[0]}="${label[1]}"}` : name;
  counters.set(key, (counters.get(key) ?? 0) + by);
}

export function renderMetrics(gauges: Record<string, number>): string {
  return [...counters, ...Object.entries(gauges)].map(([key, value]) => `${key} ${value}\n`).join("");
}
