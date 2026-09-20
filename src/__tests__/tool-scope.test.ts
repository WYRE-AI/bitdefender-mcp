import { describe, expect, it } from 'vitest';
import { ALL_TOOLS } from '../tools/index.js';

/**
 * Hard scope boundary (see README's Scope section and the PR description for
 * the full accounting against GravityZone's API guide): this connector must
 * NEVER expose a tool backed by a mutating JSON-RPC method (create/update/
 * delete/move/set/add/remove - e.g. createScanTask, moveEndpoints,
 * deleteEndpoint, createIsolateEndpointTask, addToBlocklist, createReport,
 * deleteReport). Pin the exact tool set so an accidental addition fails
 * this test immediately rather than silently shipping.
 */
describe('ALL_TOOLS scope boundary', () => {
  const EXPECTED_TOOL_NAMES = [
    // Network
    'bitdefender_list_endpoints',
    'bitdefender_get_endpoint',
    'bitdefender_list_custom_groups',
    'bitdefender_list_network_inventory',
    'bitdefender_list_scan_tasks',
    // Policies
    'bitdefender_list_policies',
    'bitdefender_get_policy',
    // Incidents
    'bitdefender_list_blocklist_items',
    // Reports
    'bitdefender_list_reports',
    'bitdefender_get_report_download_links',
  ].sort();

  it("exposes exactly this connector's 10 read-only tools - nothing more, nothing less", () => {
    const names = ALL_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(EXPECTED_TOOL_NAMES);
    expect(names).toHaveLength(10);
  });

  it('never exposes a tool backed by a mutating (create/update/delete/move/set/add/remove) method', () => {
    // Forbidden as a whole underscore-token, not a substring - so this does
    // NOT false-positive on e.g. 'bitdefender_list_reports' ('reports' has
    // no banned token) or 'bitdefender_get_report_download_links'
    // ('download'/'links' are not banned tokens).
    const FORBIDDEN_TOKENS = new Set([
      'create', 'update', 'delete', 'move', 'set', 'add', 'remove', 'restore',
    ]);

    for (const tool of ALL_TOOLS) {
      const tokens = tool.name.split('_');
      for (const token of tokens) {
        expect(
          FORBIDDEN_TOKENS.has(token),
          `Tool "${tool.name}" contains forbidden token "${token}" - this connector must stay read-only.`
        ).toBe(false);
      }
    }
  });

  it('every tool name is prefixed with bitdefender_', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name.startsWith('bitdefender_')).toBe(true);
    }
  });
});
