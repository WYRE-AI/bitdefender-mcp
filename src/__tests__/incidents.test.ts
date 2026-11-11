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

  it('bitdefender_list_incidents calls getIncidentsList on the v1.2 incidents area with filters, sort and clamped perPage', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({
        page: 1,
        pagesCount: 1,
        perPage: 100,
        total: 1,
        items: [{ incidentId: '67dd30dd4a842ebbbb0b6af3', incidentNumber: 42, status: 'open' }],
      })
    );

    const result = await runWithCredentials(creds, () =>
      handleIncidentTool('bitdefender_list_incidents', {
        filters: {
          endpointId: 'ep-1',
          status: ['open'],
          startDate: '2026-11-01T00:00:00Z',
          endDate: '2026-11-11T00:00:00Z',
        },
        sortBy: 'lastIncidentChange',
        perPage: 500,
      })
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.2/jsonrpc/incidents');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getIncidentsList');
    expect(body.params.filters.endpointId).toBe('ep-1');
    expect(body.params.options).toEqual({ sortBy: 'lastIncidentChange' });
    expect(body.params.perPage).toBe(100);
    expect(JSON.parse(textOf(result)).items[0].incidentNumber).toBe(42);
  });

  it('bitdefender_list_incidents rejects a half-sent date pair without calling fetch', async () => {
    const result = await runWithCredentials(creds, () =>
      handleIncidentTool('bitdefender_list_incidents', { filters: { startDate: '2026-11-01T00:00:00Z' } })
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('startDate and filters.endDate');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('bitdefender_get_incident calls getIncident on the v1.2 incidents area', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRpcSuccessResponse({ incidentId: '67dd30dd4a842ebbbb0b6af3', severityScore: 80, attackTypes: ['Malware'] })
    );

    const result = await runWithCredentials(creds, () =>
      handleIncidentTool('bitdefender_get_incident', { id: '67dd30dd4a842ebbbb0b6af3' })
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloud.gravityzone.bitdefender.com/v1.2/jsonrpc/incidents');
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('getIncident');
    expect(body.params).toEqual({ id: '67dd30dd4a842ebbbb0b6af3' });
    expect(JSON.parse(textOf(result)).severityScore).toBe(80);
  });

  it('bitdefender_get_incident rejects a malformed id without calling fetch', async () => {
    const result = await runWithCredentials(creds, () => handleIncidentTool('bitdefender_get_incident', { id: 'not-an-id' }));

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handleIncidentTool('bitdefender_list_blocklist_items', {});

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
