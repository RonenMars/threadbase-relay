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

const { server } = createRelay({ relayKeyPair, version: process.env.npm_package_version, log });

// A serverless host takes the exported server and does the listening itself.
if (!process.env.VERCEL) {
  const port = Number(process.env.PORT ?? 8787);
  server.listen(port, () =>
    log("relay.listening", { port, relayPublicKey: relayKeyPair.publicKeyRaw.toString("base64url") }),
  );
}

export default server;
