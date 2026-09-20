import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getPoliciesList, getPolicyDetails } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const POLICY_TOOLS: Tool[] = [
  {
    name: 'bitdefender_list_policies',
    description:
      'List security policies available to the account (id, name, owning company). Policy IDs from this response are required by bitdefender_get_policy. Returns a paginated envelope: page/pagesCount/perPage/total/items.',
    inputSchema: {
      type: 'object',
      properties: { ...PAGE_PARAMS_PROPERTIES },
    },
  },
  {
    name: 'bitdefender_get_policy',
    description:
      'Get full detail for one security policy: creator, created/last-modified dates, and its complete settings object. Requires a policy ID from bitdefender_list_policies.',
    inputSchema: {
      type: 'object',
      properties: {
        policyId: { type: 'string', description: 'Policy ID, from bitdefender_list_policies.' },
      },
      required: ['policyId'],
    },
  },
];

const TOOL_NAMES = new Set(POLICY_TOOLS.map((t) => t.name));
export function isPolicyTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handlePolicyTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'bitdefender_list_policies') {
      return textResult(
        await getPoliciesList(creds!, {
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    if (name === 'bitdefender_get_policy') {
      return textResult(await getPolicyDetails(creds!, { policyId: args.policyId as string }));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
