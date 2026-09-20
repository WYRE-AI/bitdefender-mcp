import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getBlocklistItems, getCredentials } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

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
];

const TOOL_NAMES = new Set(INCIDENT_TOOLS.map((t) => t.name));
export function isIncidentTool(name: string): boolean {
  return TOOL_NAMES.has(name);
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

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
