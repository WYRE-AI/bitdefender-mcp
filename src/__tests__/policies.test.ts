import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handlePolicyTool } from '../tools/policies.js';
import { runWithCredentials } from '../client.js';
import { jsonRpcSuccessResponse, textOf } from './test-helpers.js';

describe('handlePolicyTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('bitdefender_list_policies calls getPoliciesList on the policies area', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 1, items: [{ id: 'p1', name: 'Policy 1' }] })
    );

    const result = await runWithCredentials(creds, () => handlePolicyTool('bitdefender_list_policies', { page: 1, perPage: 2 }));

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/policies');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getPoliciesList');
    expect(body.params).toEqual({ page: 1, perPage: 2 });
    expect(result.isError).toBeUndefined();
  });

  it('bitdefender_get_policy requires policyId and calls getPolicyDetails', async () => {
    fetchMock.mockResolvedValueOnce(jsonRpcSuccessResponse({ id: 'p1', name: 'Policy 1', settings: {} }));

    const result = await runWithCredentials(creds, () => handlePolicyTool('bitdefender_get_policy', { policyId: 'p1' }));

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('getPolicyDetails');
    expect(body.params).toEqual({ policyId: 'p1' });
    expect(JSON.parse(textOf(result)).id).toBe('p1');
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handlePolicyTool('bitdefender_list_policies', {});

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
