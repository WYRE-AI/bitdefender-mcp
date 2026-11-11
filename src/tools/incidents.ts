import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getBlocklistItems, getCredentials, getIncident, getIncidentsList } from '../client.js';
import type { IncidentFilters } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

const INCIDENT_ID_PATTERN = /^[0-9a-f]{24}$/i;

/** Date filter pairs GravityZone requires together, start before end. */
const DATE_PAIRS: Array<[keyof IncidentFilters, keyof IncidentFilters]> = [
  ['startDate', 'endDate'],
  ['processedStartDate', 'processedEndDate'],
  ['changeStartDate', 'changeEndDate'],
];

const STRING_ARRAY = { type: 'array', items: { type: 'string' } } as const;

export const INCIDENT_TOOLS: Tool[] = [
  {
    name: 'bitdefender_list_blocklist_items',
    description:
      "List file hashes present in the account's Blocklist - hash, hash algorithm (SHA256/MD5), source (incident/import/manual), source description, and filename where known. Read-only - this connector never adds to or removes from the Blocklist (addToBlocklist/removeFromBlocklist are excluded; see README's Scope section). Returns a paginated envelope: page/pagesCount/perPage/total/items.",
    inputSchema: {
      type: 'object',
      properties: { ...PAGE_PARAMS_PROPERTIES },
    },
  },
  {
    name: 'bitdefender_list_incidents',
    description:
      'List EDR/XDR incidents (endpoint and organization incidents) - incidentId, incidentNumber, type, company, status, main action (reported/blocked/partially_blocked), priority and timestamps. Incident IDs from this response are required by bitdefender_get_incident. Scope to one machine with filters.endpointId (from bitdefender_list_endpoints). Needs a GravityZone license that includes incidents and an API key with the Incidents API enabled. Read-only - status, priority, notes and assignment are never changed. Returns a paginated envelope: page/pagesCount/perPage/total/items.',
    inputSchema: {
      type: 'object',
      properties: {
        filters: {
          type: 'object',
          description:
            'Optional filters; all selected filters must match. Each date pair (startDate+endDate, processedStartDate+processedEndDate, changeStartDate+changeEndDate) must be sent together, ISO 8601, start before end.',
          properties: {
            endpointId: { type: 'string', description: 'Only incidents involving this endpoint (ID from bitdefender_list_endpoints).' },
            status: { ...STRING_ARRAY, description: 'Any of: open, in_progress, closed, false_positive, closed_mdr_reviewed.' },
            priority: { ...STRING_ARRAY, description: 'Any of: unknown, low, medium, high, critical.' },
            incidentType: { ...STRING_ARRAY, description: 'incident (endpoint) and/or extendedIncident (organization).' },
            mainAction: { ...STRING_ARRAY, description: 'Any of: reported, blocked, partially_blocked.' },
            assignedUserId: { type: 'string', description: 'Only incidents assigned to this GravityZone user ID.' },
            startDate: { type: 'string', description: 'Last updated on or after (ISO 8601). Needs endDate.' },
            endDate: { type: 'string', description: 'Last updated on or before (ISO 8601). Needs startDate.' },
            processedStartDate: { type: 'string', description: 'Last processed on or after (ISO 8601). Needs processedEndDate.' },
            processedEndDate: { type: 'string', description: 'Last processed on or before (ISO 8601). Needs processedStartDate.' },
            changeStartDate: { type: 'string', description: 'Last changed (any source) on or after (ISO 8601). Needs changeEndDate.' },
            changeEndDate: { type: 'string', description: 'Last changed (any source) on or before (ISO 8601). Needs changeStartDate.' },
          },
        },
        sortBy: {
          type: 'string',
          enum: ['lastIncidentChange', 'lastUpdated'],
          description: 'Sort field, newest first. Defaults to lastUpdated.',
        },
        page: PAGE_PARAMS_PROPERTIES.page,
        perPage: { type: 'number', description: 'Items per page (10-100). Defaults to 30.' },
      },
    },
  },
  {
    name: 'bitdefender_get_incident',
    description:
      'Get full detail for one incident: severity score (1-100), priority, attack types (e.g. Malware, Ransomware, Password Stealer), detection name, affected computer (name, FQDN, IP, MACs), process/file nodes, alerts, MITRE tags, status history and the Control Center link. Requires an incident ID from bitdefender_list_incidents. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Incident ID (24 hex characters), from bitdefender_list_incidents.' },
      },
      required: ['id'],
    },
  },
];

const TOOL_NAMES = new Set(INCIDENT_TOOLS.map((t) => t.name));
export function isIncidentTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

/** Returns an error message if a date pair is half-sent, else null. */
function checkDatePairs(filters: IncidentFilters | undefined): string | null {
  if (!filters) return null;
  for (const [start, end] of DATE_PAIRS) {
    if (Boolean(filters[start]) !== Boolean(filters[end])) {
      return `filters.${start} and filters.${end} must be sent together.`;
    }
  }
  return null;
}

/** getIncidentsList accepts 10-10000 per page; cap at 100 so one call stays a readable size. */
function clampIncidentPerPage(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
  return Math.min(100, Math.max(10, Math.floor(value)));
}

export async function handleIncidentTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'bitdefender_list_blocklist_items') {
      return textResult(
        await getBlocklistItems(creds!, {
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    if (name === 'bitdefender_list_incidents') {
      const filters = args.filters as IncidentFilters | undefined;
      const pairError = checkDatePairs(filters);
      if (pairError) return errorResult(pairError);

      const sortBy = args.sortBy as 'lastIncidentChange' | 'lastUpdated' | undefined;
      return textResult(
        await getIncidentsList(creds!, {
          page: args.page as number | undefined,
          perPage: clampIncidentPerPage(args.perPage),
          filters,
          options: sortBy ? { sortBy } : undefined,
        })
      );
    }

    if (name === 'bitdefender_get_incident') {
      const id = args.id;
      if (typeof id !== 'string' || !INCIDENT_ID_PATTERN.test(id)) {
        return errorResult('id must be a 24-character hex incident ID from bitdefender_list_incidents.');
      }
      return textResult(await getIncident(creds!, { id }));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
