// Tunnel frame codec: type(1) || streamId(4, BE) || payload(<= 64 KiB).
// The relay reads only this header. Payloads are opaque bytes it forwards.

export const FRAME_TYPES = {
  OPEN: 1,
  HEAD: 2,
  DATA: 3,
  END: 4,
  RESET: 5,
  WINDOW: 6,
} as const;

export type FrameType = (typeof FRAME_TYPES)[keyof typeof FRAME_TYPES];

export const FRAME_HEADER_BYTES = 5;
export const MAX_FRAME_PAYLOAD_BYTES = 64 * 1024;
export const MAX_FRAME_BYTES = FRAME_HEADER_BYTES + MAX_FRAME_PAYLOAD_BYTES;

const KNOWN_TYPES = new Set<number>(Object.values(FRAME_TYPES));

export class FrameError extends Error {}

export interface Frame {
  type: FrameType;
  streamId: number;
  payload: Buffer;
}

export function encodeFrame(type: FrameType, streamId: number, payload: Buffer = Buffer.alloc(0)): Buffer {
  if (payload.length > MAX_FRAME_PAYLOAD_BYTES) {
    throw new FrameError(`Frame payload too large: ${payload.length}`);
  }
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  header.writeUInt8(type, 0);
  header.writeUInt32BE(streamId, 1);
  return Buffer.concat([header, payload]);
}

export function decodeFrame(bytes: Buffer): Frame {
  if (bytes.length < FRAME_HEADER_BYTES) throw new FrameError(`Frame too short: ${bytes.length}`);
  if (bytes.length > MAX_FRAME_BYTES) throw new FrameError(`Frame too large: ${bytes.length}`);
  const type = bytes.readUInt8(0);
  if (!KNOWN_TYPES.has(type)) throw new FrameError(`Unknown frame type: ${type}`);
  return {
    type: type as FrameType,
    streamId: bytes.readUInt32BE(1),
    payload: bytes.subarray(FRAME_HEADER_BYTES),
  };
}
