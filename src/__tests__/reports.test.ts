import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleReportTool } from '../tools/reports.js';
import { runWithCredentials } from '../client.js';
import { jsonRpcSuccessResponse, textOf } from './test-helpers.js';

describe('handleReportTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1', accessUrl: 'https://cloud.gravityzone.bitdefender.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('bitdefender_list_reports calls getReportsList on the reports area and forwards the type filter', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 1, items: [{ id: 'r1', name: 'My report 1', type: 2, occurrence: 2 }] })
    );

    const result = await runWithCredentials(creds, () => handleReportTool('bitdefender_list_reports', { type: 2 }));

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.0/jsonrpc/reports');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getReportsList');
    expect(body.params).toEqual({ type: 2 });
    expect(result.isError).toBeUndefined();
  });

  it('bitdefender_get_report_download_links requires reportId and calls getDownloadLinks', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({ readyForDownload: true, lastInstanceUrl: 'https://example/download/last' })
    );

    const result = await runWithCredentials(creds, () =>
      handleReportTool('bitdefender_get_report_download_links', { reportId: 'r1' })
    );

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('getDownloadLinks');
    expect(body.params).toEqual({ reportId: 'r1' });
    expect(JSON.parse(textOf(result)).readyForDownload).toBe(true);
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handleReportTool('bitdefender_list_reports', {});

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
