import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleQuarantineTool } from '../tools/quarantine.js';
import { runWithCredentials } from '../client.js';
import { jsonRpcSuccessResponse, textOf } from './test-helpers.js';

describe('handleQuarantineTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('bitdefender_list_quarantine_items calls getQuarantineItemsList on the quarantine/computers service', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({
        page: 1,
        pagesCount: 1,
        perPage: 30,
        total: 1,
        items: [
          {
            id: 'q1',
            quarantinedOn: '2026-11-05T09:00:00',
            actionStatus: 0,
            endpointId: 'ep-1',
            endpointName: 'ENDPOINT-01',
            threatName: 'Trojan.Generic.123',
            details: { filePath: 'c:\\users\\jsmith\\downloads\\invoice.exe', fileSha256: 'abc' },
          },
        ],
      })
    );

    const result = await runWithCredentials(creds, () =>
      handleQuarantineTool('bitdefender_list_quarantine_items', {
        endpointId: 'ep-1',
        filters: { startDate: '2026-11-01T00:00:00Z', threatName: 'Trojan' },
      })
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/quarantine/computers');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getQuarantineItemsList');
    expect(body.params.endpointId).toBe('ep-1');
    expect(body.params.filters.threatName).toBe('Trojan');
    expect(JSON.parse(textOf(result)).items[0].threatName).toBe('Trojan.Generic.123');
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    vi.stubEnv('BITDEFENDER_API_KEY', '');
    vi.stubEnv('BITDEFENDER_ACCESS_URL', '');
    const result = await handleQuarantineTool('bitdefender_list_quarantine_items', {});

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
