import { decodeFrame, encodeFrame, FRAME_TYPES, FrameError, MAX_FRAME_PAYLOAD_BYTES } from "../src/frames";

describe("tunnel frames", () => {
  it("round-trips type, stream id and payload", () => {
    const frame = decodeFrame(encodeFrame(FRAME_TYPES.DATA, 0xdeadbeef, Buffer.from("opaque")));
    expect(frame).toEqual({ type: FRAME_TYPES.DATA, streamId: 0xdeadbeef, payload: Buffer.from("opaque") });
  });

  it("accepts a payload at the cap and refuses one byte over, both ways", () => {
    const atCap = Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES);
    expect(decodeFrame(encodeFrame(FRAME_TYPES.DATA, 1, atCap)).payload.length).toBe(MAX_FRAME_PAYLOAD_BYTES);

    const over = Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES + 1);
    expect(() => encodeFrame(FRAME_TYPES.DATA, 1, over)).toThrow(FrameError);
    expect(() => decodeFrame(Buffer.concat([Buffer.from([FRAME_TYPES.DATA, 0, 0, 0, 1]), over]))).toThrow(FrameError);
  });

  it("refuses a truncated header and an unknown type", () => {
    expect(() => decodeFrame(Buffer.from([FRAME_TYPES.DATA, 0, 0, 0]))).toThrow(FrameError);
    expect(() => decodeFrame(Buffer.from([0, 0, 0, 0, 1]))).toThrow(FrameError);
    expect(() => decodeFrame(Buffer.from([99, 0, 0, 0, 1]))).toThrow(FrameError);
  });
});
