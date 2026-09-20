import type { BitdefenderCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: BitdefenderCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No Bitdefender credentials configured. Set BITDEFENDER_API_KEY and BITDEFENDER_ACCESS_URL.');
  }
  return null;
}

/** Shared input-schema fragment for the paginated list endpoints. */
export const PAGE_PARAMS_PROPERTIES = {
  page: { type: 'number', description: 'Results page number (1-based). Defaults to 1.' },
  perPage: { type: 'number', description: 'Items per page (max 100). Defaults to 30.' },
} as const;
