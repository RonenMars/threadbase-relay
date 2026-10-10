import http from "http";
import { generateKeyPair, keyPairFromRawPrivate } from "./noise/noise";
import { createRelay } from "./relay";

// RELAY_STATIC_KEY is the relay's X25519 private key, 32 raw bytes as base64url.
// Streamers pin the matching public key, so production must not invent one.
function loadRelayKeyPair() {
  const encoded = process.env.RELAY_STATIC_KEY;
  if (encoded) return keyPairFromRawPrivate(Buffer.from(encoded, "base64url"));
  if (process.env.NODE_ENV === "production") {
    throw new Error("RELAY_STATIC_KEY is required in production");
  }
  return generateKeyPair();
}

const relayKeyPair = loadRelayKeyPair();
const log = (event: string, fields: Record<string, string | number> = {}) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), event, ...fields }));

const { server, drain, metrics } = createRelay({ relayKeyPair, version: process.env.npm_package_version, log });

// Inside fly.toml's kill_timeout, which is when the platform stops asking.
const DRAIN_DEADLINE_MS = 8_000;

// A serverless host takes the exported server and does the listening itself.
if (!process.env.VERCEL) {
  const port = Number(process.env.PORT ?? 8787);
  server.listen(port, () =>
    log("relay.listening", { port, relayPublicKey: relayKeyPair.publicKeyRaw.toString("base64url") }),
  );
  // Its own port, which fly.toml's [metrics] scrapes and the public service never maps.
  if (process.env.METRICS_PORT) {
    http
      .createServer((req, res) => {
        const found = req.url === "/metrics";
        res.writeHead(found ? 200 : 404, { "content-type": "text/plain; version=0.0.4" });
        res.end(found ? metrics() : "");
      })
      .listen(Number(process.env.METRICS_PORT));
  }
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => void drain(DRAIN_DEADLINE_MS).finally(() => process.exit(0)));
  }
}

export default server;
