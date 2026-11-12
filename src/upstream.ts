import { BitdefenderApiError } from './types.js';

export const MAX_UPSTREAM_BYTES_DEFAULT = 16 * 1024 * 1024;
export const MAX_UPSTREAM_BYTES_CEILING = 128 * 1024 * 1024;

function positiveInt(raw: string | undefined, fallback: number, max: number): number {
  const value = (raw ?? '').trim();
  if (!/^\d+$/.test(value)) return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, max);
}

/** Always bounds upstream responses, even when the environment value is invalid. */
export function maxUpstreamBytes(): number {
  return positiveInt(process.env.BITDEFENDER_MAX_UPSTREAM_BYTES, MAX_UPSTREAM_BYTES_DEFAULT, MAX_UPSTREAM_BYTES_CEILING);
}

/** Reads UTF-8 text, cancelling oversized responses before JSON parsing. */
export async function readBoundedText(res: Response, maxBytes: number, where: string): Promise<string> {
  const tooLarge = () => new BitdefenderApiError(
    `GravityZone response for ${where} exceeded ${maxBytes} bytes; narrow the query with filters or pagination, or raise BITDEFENDER_MAX_UPSTREAM_BYTES.`,
  );
  const declared = Number.parseInt(res.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw tooLarge();
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}
