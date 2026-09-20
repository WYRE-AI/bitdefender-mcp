import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { NETWORK_TOOLS, handleNetworkTool, isNetworkTool } from './network.js';
import { POLICY_TOOLS, handlePolicyTool, isPolicyTool } from './policies.js';
import { INCIDENT_TOOLS, handleIncidentTool, isIncidentTool } from './incidents.js';
import { REPORT_TOOLS, handleReportTool, isReportTool } from './reports.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [
  ...NETWORK_TOOLS,
  ...POLICY_TOOLS,
  ...INCIDENT_TOOLS,
  ...REPORT_TOOLS,
];

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (isNetworkTool(name)) return handleNetworkTool(name, args);
  if (isPolicyTool(name)) return handlePolicyTool(name, args);
  if (isIncidentTool(name)) return handleIncidentTool(name, args);
  if (isReportTool(name)) return handleReportTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}
