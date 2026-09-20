import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleNetworkTool } from '../tools/network.js';
import { runWithCredentials } from '../client.js';
import { jsonRpcSuccessResponse, textOf } from './test-helpers.js';

describe('handleNetworkTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('bitdefender_list_endpoints calls getEndpointsList on the network area and forwards filters', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 1, items: [{ id: 'e1', name: 'Endpoint 1' }] })
    );

    const result = await runWithCredentials(creds, () =>
      handleNetworkTool('bitdefender_list_endpoints', {
        parentId: 'g1',
        isManaged: true,
        filters: { security: { management: { managedWithBest: true } } },
      })
    );

    expect(result.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/network');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getEndpointsList');
    expect(body.params).toMatchObject({ parentId: 'g1', isManaged: true });
    expect(JSON.parse(textOf(result)).items[0].id).toBe('e1');
  });

  it('bitdefender_get_endpoint requires endpointId and calls getManagedEndpointDetails', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ id: 'e1', name: 'Endpoint 1', state: 1 }));

    const result = await runWithCredentials(creds, () => handleNetworkTool('bitdefender_get_endpoint', { endpointId: 'e1' }));

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('getManagedEndpointDetails');
    expect(body.params).toEqual({ endpointId: 'e1' });
    expect(result.isError).toBeUndefined();
  });

  it('bitdefender_list_custom_groups calls getCustomGroupsList and returns a plain array result', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse([{ id: 'g1', name: 'myGroup1' }]));

    const result = await runWithCredentials(creds, () => handleNetworkTool('bitdefender_list_custom_groups', {}));

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('getCustomGroupsList');
    expect(JSON.parse(textOf(result))).toEqual([{ id: 'g1', name: 'myGroup1' }]);
  });

  it('bitdefender_list_network_inventory calls getNetworkInventoryItems on the network area', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 0, items: [] }));

    await runWithCredentials(creds, () =>
      handleNetworkTool('bitdefender_list_network_inventory', { filters: { type: { computers: true } } })
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/network');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getNetworkInventoryItems');
    expect(body.params.filters).toEqual({ type: { computers: true } });
  });

  it('bitdefender_list_scan_tasks forwards status and name filters to getScanTasksList', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 0, items: [] }));

    await runWithCredentials(creds, () => handleNetworkTool('bitdefender_list_scan_tasks', { status: 2, name: 'nightly' }));

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('getScanTasksList');
    expect(body.params).toMatchObject({ status: 2, name: 'nightly' });
  });

  it('surfaces a 401 as a readable auth error rather than throwing', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 401 }));

    const result = await runWithCredentials(creds, () => handleNetworkTool('bitdefender_list_endpoints', {}));

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/rejected the API key/i);
  });

  it('surfaces a 403 as a readable per-area authorization error', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 403 }));

    const result = await runWithCredentials(creds, () => handleNetworkTool('bitdefender_list_endpoints', {}));

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/network.*API.*key/i);
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handleNetworkTool('bitdefender_list_endpoints', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/BITDEFENDER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
