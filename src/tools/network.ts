import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getCredentials,
  getCustomGroupsList,
  getEndpointsList,
  getManagedEndpointDetails,
  getNetworkInventoryItems,
  getScanTasksList,
} from '../client.js';
import type { EndpointFilters, NetworkInventoryFilters } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

const ENDPOINT_FILTERS_SCHEMA = {
  type: 'object',
  description:
    'Optional filters, structured in sections/subsections (any selected filter within a subsection matches; matches across sections AND). Some filters require a specific GravityZone license to be active, otherwise they are silently ignored.',
  properties: {
    security: {
      type: 'object',
      properties: {
        management: {
          type: 'object',
          properties: {
            managedWithBest: { type: 'boolean', description: 'Endpoints with the security agent installed.' },
            managedExchangeServers: { type: 'boolean', description: 'Protected Exchange servers (requires Security for Exchange).' },
            managedRelays: { type: 'boolean', description: 'Endpoints with the Relay role.' },
            securityServers: { type: 'boolean', description: 'Security Server appliances.' },
          },
        },
      },
    },
    depth: {
      type: 'object',
      properties: {
        allItemsRecursively: { type: 'boolean', description: 'Include endpoints recursively within the Network Inventory.' },
      },
    },
    details: {
      type: 'object',
      properties: {
        ssid: { type: 'string', description: 'Filter by Active Directory SID, regardless of protection status.' },
        macs: { type: 'array', items: { type: 'string' }, description: 'Filter by MAC address(es), regardless of protection status.' },
      },
    },
  },
} as const;

const NETWORK_INVENTORY_FILTERS_SCHEMA = {
  ...ENDPOINT_FILTERS_SCHEMA,
  properties: {
    type: {
      type: 'object',
      properties: {
        groups: { type: 'boolean', description: 'Custom groups of endpoints.' },
        ec2Instances: { type: 'boolean', description: 'Amazon EC2 instances.' },
        computers: { type: 'boolean', description: 'Computers.' },
        virtualMachines: { type: 'boolean', description: 'Virtual machines.' },
      },
    },
    ...ENDPOINT_FILTERS_SCHEMA.properties,
  },
} as const;

export const NETWORK_TOOLS: Tool[] = [
  {
    name: 'bitdefender_list_endpoints',
    description:
      "List managed/unmanaged endpoints (computers, VMs, EC2 instances) - name, FQDN, IP, MAC addresses, AD SID, group, and installed-agent flags. Endpoint IDs from this response are required by bitdefender_get_endpoint. Scope to a group with parentId (from bitdefender_list_custom_groups); omit for the root of the Network Inventory. Returns a paginated envelope: page/pagesCount/perPage/total/items.",
    inputSchema: {
      type: 'object',
      properties: {
        parentId: { type: 'string', description: 'Group ID to scope the listing to. Defaults to Computers and Groups (root).' },
        isManaged: { type: 'boolean', description: 'True to return only managed endpoints. Omit to return both managed and unmanaged.' },
        filters: ENDPOINT_FILTERS_SCHEMA,
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'bitdefender_get_endpoint',
    description:
      "Get full detail for one managed endpoint: power state, IP, last-seen timestamp, and the installed security agent's engine/product versions, license status, and update/outdated flags. Requires an endpoint ID from bitdefender_list_endpoints.",
    inputSchema: {
      type: 'object',
      properties: {
        endpointId: { type: 'string', description: 'Endpoint ID, from bitdefender_list_endpoints.' },
      },
      required: ['endpointId'],
    },
  },
  {
    name: 'bitdefender_list_custom_groups',
    description:
      "List the child groups directly under a group in the Network Inventory tree. Omit parentId to list the top-level 'Computers and Groups' and 'Deleted' groups. Group IDs from this response can be passed as parentId to bitdefender_list_endpoints and bitdefender_list_network_inventory. Returns a plain array (not a paginated envelope), each entry {id, name}.",
    inputSchema: {
      type: 'object',
      properties: {
        parentId: { type: 'string', description: 'Parent group ID. Omit for the top-level groups.' },
      },
    },
  },
  {
    name: 'bitdefender_list_network_inventory',
    description:
      'List Network Inventory items (groups, computers, virtual machines, EC2 instances) under a container, with per-type detail. Broader than bitdefender_list_endpoints, which returns only endpoints - this also returns group nodes and lets you filter by item type. Returns a paginated envelope: page/pagesCount/perPage/total/items.',
    inputSchema: {
      type: 'object',
      properties: {
        parentId: { type: 'string', description: 'Container ID to scope the listing to. Defaults to the root of the Network Inventory.' },
        filters: NETWORK_INVENTORY_FILTERS_SCHEMA,
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'bitdefender_list_scan_tasks',
    description:
      "List previously created on-demand scan tasks and their status (1=Pending, 2=In progress, 3=Finished). Read-only - this connector never creates a scan task (createScanTask is excluded; see README's Scope section). Returns a paginated envelope: page/pagesCount/perPage/total/items.",
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: "Filter by task name. Prefix with '*' to match anywhere in the name; otherwise matches names starting with the keyword." },
        status: { type: 'number', enum: [1, 2, 3], description: '1=Pending, 2=In progress, 3=Finished.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
];

const TOOL_NAMES = new Set(NETWORK_TOOLS.map((t) => t.name));
export function isNetworkTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleNetworkTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'bitdefender_list_endpoints') {
      return textResult(
        await getEndpointsList(creds!, {
          parentId: args.parentId as string | undefined,
          isManaged: args.isManaged as boolean | undefined,
          filters: args.filters as EndpointFilters | undefined,
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    if (name === 'bitdefender_get_endpoint') {
      return textResult(await getManagedEndpointDetails(creds!, { endpointId: args.endpointId as string }));
    }

    if (name === 'bitdefender_list_custom_groups') {
      return textResult(await getCustomGroupsList(creds!, { parentId: args.parentId as string | undefined }));
    }

    if (name === 'bitdefender_list_network_inventory') {
      return textResult(
        await getNetworkInventoryItems(creds!, {
          parentId: args.parentId as string | undefined,
          filters: args.filters as NetworkInventoryFilters | undefined,
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    if (name === 'bitdefender_list_scan_tasks') {
      return textResult(
        await getScanTasksList(creds!, {
          name: args.name as string | undefined,
          status: args.status as 1 | 2 | 3 | undefined,
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
