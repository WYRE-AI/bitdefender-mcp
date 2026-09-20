import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getDownloadLinks, getReportsList } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const REPORT_TOOLS: Tool[] = [
  {
    name: 'bitdefender_list_reports',
    description:
      'List scheduled/instant reports configured on the account - id, name, report type, and run occurrence (hourly/daily/weekly/monthly). Report IDs from this response are required by bitdefender_get_report_download_links. Returns a paginated envelope: page/pagesCount/perPage/total/items.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Filter by report name.' },
        type: {
          type: 'number',
          description:
            'Filter by report type: 1 Antiphishing Activity, 2 Blocked Applications, 3 Blocked Websites, 5 Data Protection, 6 Device Control Activity, 7 Endpoint Modules Status, 8 Endpoint Protection Status, 9 Firewall Activity, 11 Malware Activity, 12 Malware Status, 13 Monthly License Usage, 14 Network Status, 15 On demand scanning, 16 Policy Compliance, 17 Security Audit, 18 Security Server Status, 19 Top 10 Detected Malware, 21 Top 10 Infected Endpoints, 22 Update Status, 23 Upgrade Status, 24 AWS Monthly Usage.',
        },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'bitdefender_get_report_download_links',
    description:
      "Check whether a report is ready for download and, if so, get its download URL(s) - readyForDownload, lastInstanceUrl (most recent instance), and allInstancesUrl (scheduled reports only). Both URLs require the same HTTP Basic auth as the API itself (API key as username, empty password) and return a CSV+PDF archive. Requires a report ID from bitdefender_list_reports.",
    inputSchema: {
      type: 'object',
      properties: {
        reportId: { type: 'string', description: 'Report ID, from bitdefender_list_reports.' },
      },
      required: ['reportId'],
    },
  },
];

const TOOL_NAMES = new Set(REPORT_TOOLS.map((t) => t.name));
export function isReportTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleReportTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'bitdefender_list_reports') {
      return textResult(
        await getReportsList(creds!, {
          name: args.name as string | undefined,
          type: args.type as number | undefined,
          page: args.page as number | undefined,
          perPage: args.perPage as number | undefined,
        })
      );
    }

    if (name === 'bitdefender_get_report_download_links') {
      return textResult(await getDownloadLinks(creds!, { reportId: args.reportId as string }));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
