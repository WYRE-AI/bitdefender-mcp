import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getQuarantineItemsList } from '../client.js';
import type { QuarantineFilters } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const QUARANTINE_TOOLS: Tool[] = [
  {
    name: 'bitdefender_list_quarantine_items',
    description:
      "List files quarantined on computers and virtual machines - threat name, file path, file SHA256, endpoint name/IP/ID, quarantine date and pending action status. This is the record of what the antimalware engine actually caught, including detections already cleaned. Scope to one machine with endpointId (from bitdefender_list_endpoints), or omit it for the whole network of the key's company. Needs an API key with the Quarantine API enabled. Read-only - never removes or restores a quarantined file (createRemove/createRestore quarantine tasks are excluded). Returns a paginated envelope: page/pagesCount/perPage/total/items.",
    inputSchema: {
      type: 'object',
      properties: {
        endpointId: { type: 'string', description: 'Only items from this endpoint (ID from bitdefender_list_endpoints). Omit for the whole network.' },
        filters: {
          type: 'object',
          description: 'Optional filters; all selected filters must match. Text filters match partially; a leading * matches as a suffix (e.g. "*invoice.exe").',
          properties: {
            threatName: { type: 'string', description: 'Threat name (partial match).' },
            startDate: { type: 'string', description: 'Quarantined on or after (ISO 8601).' },
            endDate: { type: 'string', description: 'Quarantined on or before (ISO 8601).' },
            filePath: { type: 'string', description: 'File path (partial match).' },
            fileSha256: { type: 'string', description: 'File SHA256 (partial match).' },
            ip: { type: 'string', description: 'Endpoint IP (partial match).' },
            actionStatus: {
              type: 'number',
              enum: [0, 1, 2, 3, 4],
              description: '0 None, 1 Pending remove, 2 Pending restore, 3 Remove failed, 4 Restore failed. Leave unset to see everything - setting 0 hides items with a pending or failed action.',
            },
          },
        },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
];

const TOOL_NAMES = new Set(QUARANTINE_TOOLS.map((t) => t.name));
export function isQuarantineTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleQuarantineTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'bitdefender_list_quarantine_items') {
      return textResult(
        await getQuarantineItemsList(creds!, {
          endpointId: args.endpointId as string | undefined,
          filters: args.filters as QuarantineFilters | undefined,
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
