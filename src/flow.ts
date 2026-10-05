import { MAX_FRAME_PAYLOAD_BYTES } from "./frames";

// Credit-based flow control for one direction of one stream. A sender starts
// with a full window and may never send more DATA than the credit it holds; the
// receiver grants credit back (a WINDOW frame) as it drains bytes to the next
// hop. So a slow hop stalls its own stream and nothing queues without bound.

export const STREAM_WINDOW_BYTES = 256 * 1024;

export class FlowError extends Error {}

/** Parse a WINDOW payload. Throws on anything that is not a positive byte count. */
export function parseCredit(payload: Buffer): number {
  let credit: unknown;
  try {
    credit = (JSON.parse(payload.toString("utf-8")) as { credit?: unknown }).credit;
  } catch {
    credit = undefined;
  }
  if (!Number.isInteger(credit) || (credit as number) <= 0) throw new FlowError("Malformed WINDOW");
  return credit as number;
}

export const encodeCredit = (credit: number) => Buffer.from(JSON.stringify({ credit }), "utf-8");

export interface FlowSender {
  write(chunk: Buffer): void;
  /** Credit arrived. Throws if the peer grants more than the window allows. */
  grant(credit: number): void;
  /** Run `done` once everything written has been sent. */
  end(done: () => void): void;
}

/**
 * Sends `source`'s bytes as DATA no faster than credit allows, pausing the
 * source while bytes wait. At most one source chunk is ever held here.
 */
export function createFlowSender(
  emit: (payload: Buffer) => void,
  source: { pause(): unknown; resume(): unknown },
): FlowSender {
  let credit = STREAM_WINDOW_BYTES;
  const queue: Buffer[] = [];
  let onDrained: (() => void) | null = null;

  const flush = () => {
    while (queue.length > 0 && credit > 0) {
      const head = queue[0];
      const size = Math.min(head.length, credit, MAX_FRAME_PAYLOAD_BYTES);
      credit -= size;
      if (size === head.length) queue.shift();
      else queue[0] = head.subarray(size);
      emit(head.subarray(0, size));
    }
    if (queue.length > 0) return void source.pause();
    source.resume();
    const done = onDrained;
    onDrained = null;
    done?.();
  };

  return {
    write(chunk) {
      queue.push(chunk);
      flush();
    },
    grant(more) {
      if (credit + more > STREAM_WINDOW_BYTES) throw new FlowError("Credit exceeds the window");
      credit += more;
      flush();
    },
    end(done) {
      if (queue.length === 0) done();
      else onDrained = done;
    },
  };
}

export interface FlowReceiver {
  /** Account for received DATA. False means the peer sent more than it was granted. */
  accept(bytes: number): boolean;
  /** Those bytes reached the next hop: grant the credit back. */
  drained(bytes: number): void;
}

export function createFlowReceiver(grant: (credit: number) => void): FlowReceiver {
  let outstanding = 0;
  return {
    accept(bytes) {
      outstanding += bytes;
      return outstanding <= STREAM_WINDOW_BYTES;
    },
    drained(bytes) {
      if (bytes === 0) return;
      outstanding -= bytes;
      grant(bytes);
    },
  };
}
