export class BodyLimitError extends Error {}
/** Bound memory before decoding/parsing untrusted HTTP bodies. */
export async function readLimited(body: ReadableStream<Uint8Array> | null, limit: number): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      bytes += value.byteLength;
      if (bytes > limit) { await reader.cancel(); throw new BodyLimitError('请求或响应过大'); }
      text += decoder.decode(value, { stream: true });
    }
  } finally { reader.releaseLock(); }
}
