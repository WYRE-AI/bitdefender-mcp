import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleIncidentTool } from '../tools/incidents.js';
import { runWithCredentials } from '../client.js';
import { jsonRpcSuccessResponse, textOf } from './test-helpers.js';

describe('handleIncidentTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('bitdefender_list_blocklist_items calls getBlocklistItems on the incidents area', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({
        page: 1,
        pagesCount: 1,
        perPage: 30,
        total: 1,
        items: [{ id: 'h1', hash: '098f6bcd4621d373cade4e832627b4f6', hashType: 2, source: 3 }],
      })
    );

    const result = await runWithCredentials(creds, () => handleIncidentTool('bitdefender_list_blocklist_items', {}));

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/incidents');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getBlocklistItems');
    expect(JSON.parse(textOf(result)).items[0].hash).toBe('098f6bcd4621d373cade4e832627b4f6');
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handleIncidentTool('bitdefender_list_blocklist_items', {});

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
