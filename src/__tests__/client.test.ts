import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { jsonRpcCall } from '../client.js';
import { BitdefenderApiError, BitdefenderAuthError, BitdefenderForbiddenError, BitdefenderRateLimitError } from '../types.js';
import { httpErrorResponse, jsonRpcErrorResponse, jsonRpcSuccessResponse } from './test-helpers.js';

/**
 * Dedicated tests for the JSON-RPC 2.0 request/response shape itself
 * (client.ts's jsonRpcCall) - the genuinely new call shape for this
 * codebase. Every other sidecar test suite in this catalog only needs to
 * assert a REST path/query/Bearer-header; this connector additionally
 * needs to prove the JSON-RPC envelope (id/jsonrpc/method/params on the
 * way out, result-vs-error on the way back) and the HTTP Basic auth header
 * (API key as username, empty password) are built correctly - none of
 * that is exercised by mocking fetch down to a bare "it returns JSON".
 */
describe('jsonRpcCall', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'test-key-123', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('POSTs a well-formed JSON-RPC 2.0 envelope to the area-specific URL', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ items: [] }));

    await jsonRpcCall(creds, 'network', 'getEndpointsList', { parentId: 'g1' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];

    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/network');
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body as string);
    expect(body.jsonrpc).toBe('2.0');
    expect(body.method).toBe('getEndpointsList');
    expect(body.params).toEqual({ parentId: 'g1' });
    expect(typeof body.id).toBe('string');
    expect(body.id.length).toBeGreaterThan(0);
  });

  it('builds the Authorization header as HTTP Basic with the API key as username and an empty password', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse([]));

    await jsonRpcCall(creds, 'network', 'getCustomGroupsList', {});

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    const expected = `Basic ${Buffer.from('test-key-123:').toString('base64')}`;
    expect(headers.Authorization).toBe(expected);
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('targets a different URL per API area for the same credentials', async () => {
    // mockImplementation (not mockResolvedValue) - a Response body can only
    // be read once, so reusing one Response instance across three calls
    // would fail the second res.json() with "Body has already been read".
    fetchMock.mockImplementation(() => Promise.resolve(jsonRpcSuccessResponse({ items: [] })));

    await jsonRpcCall(creds, 'policies', 'getPoliciesList', {});
    await jsonRpcCall(creds, 'reports', 'getReportsList', {});
    await jsonRpcCall(creds, 'incidents', 'getBlocklistItems', {});

    const urls = fetchMock.mock.calls.map((call) => call[0]);
    expect(urls).toEqual([
      'https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/policies',
      'https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/reports',
      'https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/incidents',
    ]);
  });

  it('strips a trailing slash from accessUrl before appending the jsonrpc path', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse([]));

    await jsonRpcCall({ ...creds, accessUrl: 'https://cloud.gravityzone.bitdefender.com/' }, 'network', 'getCustomGroupsList', {});

    expect(fetchMock.mock.calls[0][0]).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/network');
  });

  it('returns the `result` member on a successful JSON-RPC envelope', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ items: [{ id: 'e1' }], total: 1 }));

    const result = await jsonRpcCall(creds, 'network', 'getEndpointsList', {});

    expect(result).toEqual({ items: [{ id: 'e1' }], total: 1 });
  });

  it('throws BitdefenderApiError on a JSON-RPC-level error even though the HTTP status is 200', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcErrorResponse(-32602, 'Invalid params', 'endpointId is required'));

    await expect(jsonRpcCall(creds, 'network', 'getManagedEndpointDetails', {})).rejects.toThrow(BitdefenderApiError);

    fetchMock.mockResolvedValueOnce(jsonRpcErrorResponse(-32602, 'Invalid params', 'endpointId is required'));
    try {
      await jsonRpcCall(creds, 'network', 'getManagedEndpointDetails', {});
      expect.fail('expected jsonRpcCall to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(BitdefenderApiError);
      expect((err as BitdefenderApiError).rpcCode).toBe(-32602);
      expect((err as BitdefenderApiError).rpcMessage).toBe('Invalid params');
      expect((err as BitdefenderApiError).message).toMatch(/endpointId is required/);
    }
  });

  it('throws BitdefenderAuthError on HTTP 401 (bad/missing API key)', async () => {
    fetchMock.mockResolvedValueOnce(httpErrorResponse(401));

    await expect(jsonRpcCall(creds, 'network', 'getEndpointsList', {})).rejects.toThrow(BitdefenderAuthError);
  });

  it('throws BitdefenderForbiddenError on HTTP 403 (API area not enabled for this key)', async () => {
    fetchMock.mockResolvedValueOnce(httpErrorResponse(403));

    await expect(jsonRpcCall(creds, 'incidents', 'getBlocklistItems', {})).rejects.toThrow(BitdefenderForbiddenError);
    fetchMock.mockResolvedValueOnce(httpErrorResponse(403));
    await expect(jsonRpcCall(creds, 'incidents', 'getBlocklistItems', {})).rejects.toThrow(/incidents/);
  });

  it('throws BitdefenderRateLimitError on HTTP 429 (more than 10 req/s)', async () => {
    fetchMock.mockResolvedValueOnce(httpErrorResponse(429));

    await expect(jsonRpcCall(creds, 'reports', 'getReportsList', {})).rejects.toThrow(BitdefenderRateLimitError);
  });

  it('throws BitdefenderApiError on any other unexpected HTTP status', async () => {
    fetchMock.mockResolvedValueOnce(httpErrorResponse(500));

    await expect(jsonRpcCall(creds, 'network', 'getEndpointsList', {})).rejects.toThrow(BitdefenderApiError);
  });
});
