export class RequestTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`Request body is too large (maximum ${maxBytes} bytes).`);
    this.name = "RequestTooLargeError";
  }
}

/** Parse JSON without first buffering an unbounded request body. */
export async function readBoundedJson(
  request: Request,
  maxBytes: number,
): Promise<unknown> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && /^\d+$/.test(contentLength.trim())) {
    if (Number(contentLength) > maxBytes) throw new RequestTooLargeError(maxBytes);
  }

  if (!request.body) return JSON.parse("");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RequestTooLargeError(maxBytes);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}
