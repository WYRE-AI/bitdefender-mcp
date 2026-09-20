import type { CallToolResult } from '../tools/types.js';

/** Extracts the text of the first content block, failing loudly if it isn't text. */
export function textOf(result: CallToolResult): string {
  const block = result.content?.[0];
  if (!block || block.type !== 'text') {
    throw new Error(`Expected a text content block, got: ${JSON.stringify(block)}`);
  }
  return block.text;
}

/** Builds a raw HTTP Response wrapping a successful JSON-RPC 2.0 envelope, matching GravityZone's response shape. */
export function jsonRpcSuccessResponse(result: unknown, requestId = 'test-id'): Response {
  return new Response(JSON.stringify({ id: requestId, jsonrpc: '2.0', result }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Builds a raw HTTP Response wrapping a JSON-RPC 2.0 error envelope (HTTP 200 with a body `error` member). */
export function jsonRpcErrorResponse(
  code: number,
  message: string,
  details?: string,
  requestId = 'test-id'
): Response {
  return new Response(
    JSON.stringify({
      id: requestId,
      jsonrpc: '2.0',
      error: { code, message, data: details ? { details } : undefined },
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  );
}

/** Builds a raw (non-JSON-RPC) HTTP failure Response, e.g. for 401/403/429 which GravityZone signals at the HTTP layer. */
export function httpErrorResponse(status: number, body: unknown = { error: 'error' }): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
