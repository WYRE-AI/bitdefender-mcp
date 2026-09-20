import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { logger } from './utils/logger.js';
import {
  BitdefenderApiError,
  BitdefenderAuthError,
  BitdefenderForbiddenError,
  BitdefenderRateLimitError,
} from './types.js';
import type {
  BitdefenderApiArea,
  BitdefenderCredentials,
  BitdefenderPagedResponse,
  GetBlocklistItemsParams,
  GetCustomGroupsListParams,
  GetDownloadLinksParams,
  GetEndpointsListParams,
  GetManagedEndpointDetailsParams,
  GetNetworkInventoryItemsParams,
  GetPoliciesListParams,
  GetPolicyDetailsParams,
  GetReportsListParams,
  GetScanTasksListParams,
} from './types.js';

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey, accessUrl}); getCredentials()
// reads from it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<BitdefenderCredentials>();

export function runWithCredentials<T>(creds: BitdefenderCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): BitdefenderCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey && scoped?.accessUrl) return scoped;
  const apiKey = process.env.BITDEFENDER_API_KEY;
  const accessUrl = process.env.BITDEFENDER_ACCESS_URL;
  if (!apiKey || !accessUrl) {
    logger.warn('Missing credentials', { hasApiKey: !!apiKey, hasAccessUrl: !!accessUrl });
    return null;
  }
  return { apiKey, accessUrl };
}

// ---------------------------------------------------------------------
// JSON-RPC 2.0 request helper — GENUINELY NEW SHAPE FOR THIS CODEBASE.
//
// Every other Conduit sidecar (Cork, CyberQP, Slide, UniFi, Cisco Duo) calls
// a plain REST API: one base URL, verb+path identifies the operation,
// params ride in the query string or JSON body. GravityZone instead exposes
// several SEPARATE JSON-RPC 2.0 endpoints (one per product area - network,
// policies, reports, incidents, ...), and EVERY call to a given area,
// regardless of what it does, is an HTTP POST to that same area URL with an
// identical envelope:
//
//   POST <accessUrl>/v1.0/jsonrpc/<area>
//   { "id": "<uuid>", "jsonrpc": "2.0", "method": "<methodName>", "params": {...} }
//
// The operation itself lives entirely INSIDE the body (`method` + `params`),
// never in the URL or HTTP verb - there is no GET/POST/PATCH/DELETE
// distinction to key off of, which is exactly why this connector's hard
// read-only scope boundary is enforced by only ever calling documented
// getXxx/listXxx METHOD NAMES (see tools/*.ts), not by restricting HTTP
// verbs the way every REST sidecar in this catalog does.
//
// Auth is also a new shape here (see types.ts's BitdefenderCredentials
// doc-comment): HTTP Basic with the API key as username and an empty
// password, not a bearer token. So unlike every other sidecar's
// doGet()/doPost() (one shared base URL, one Authorization header shape),
// this client needs (a) an `area` parameter to select which of the four
// JSON-RPC endpoints to POST to, and (b) a Basic-auth header built fresh
// per call from the two credential fields rather than a single static
// header value threaded through from vendor-config.ts's headerMapping (see
// vendor-config.ts's bitdefender entry comment for how that maps onto
// buildHeaders).
// ---------------------------------------------------------------------

function buildBasicAuthHeader(apiKey: string): string {
  return `Basic ${Buffer.from(`${apiKey}:`).toString('base64')}`;
}

interface JsonRpcSuccess<T> {
  id: string;
  jsonrpc: '2.0';
  result: T;
}

interface JsonRpcFailure {
  id: string;
  jsonrpc: '2.0';
  error: { code: number; message: string; data?: { details?: string } };
}

type JsonRpcResponse<T> = JsonRpcSuccess<T> | JsonRpcFailure;

function isJsonRpcFailure(body: unknown): body is JsonRpcFailure {
  return typeof body === 'object' && body !== null && 'error' in body;
}

/**
 * POSTs one JSON-RPC 2.0 request to a GravityZone API area and returns
 * `result`. Exported (not just used internally) so tests can exercise the
 * envelope/auth-header construction directly, not only through a tool
 * handler.
 */
export async function jsonRpcCall<T>(
  creds: BitdefenderCredentials,
  area: BitdefenderApiArea,
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const url = `${creds.accessUrl.replace(/\/+$/, '')}/v1.0/jsonrpc/${area}`;
  const requestId = randomUUID();

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: buildBasicAuthHeader(creds.apiKey),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ id: requestId, jsonrpc: '2.0', method, params }),
    signal: AbortSignal.timeout(15_000),
  });

  // GravityZone signals auth/authorization/rate-limit failures at the HTTP
  // layer (distinct HTTP status codes), separately from JSON-RPC-level
  // errors (HTTP 200 with a body `error` member) - both are handled below.
  // See README's Authentication section for the full status-code table.
  if (res.status === 401) {
    throw new BitdefenderAuthError(`GravityZone rejected the API key (HTTP 401): ${area}/${method}`);
  }
  if (res.status === 403) {
    throw new BitdefenderForbiddenError(
      `GravityZone denied access to the "${area}" API for this key (HTTP 403). ` +
        `The API key must have the ${area} API selected at generation time — see README's Authentication section.`,
    );
  }
  if (res.status === 429) {
    throw new BitdefenderRateLimitError(`GravityZone rate-limited the request (HTTP 429): ${area}/${method}`);
  }
  if (!res.ok) {
    throw new BitdefenderApiError(`GravityZone ${area}/${method} failed: HTTP ${res.status}`, res.status);
  }

  const body = (await res.json()) as JsonRpcResponse<T>;
  if (isJsonRpcFailure(body)) {
    const detail = body.error.data?.details;
    throw new BitdefenderApiError(
      `GravityZone ${area}/${method} returned a JSON-RPC error: ${body.error.message}${detail ? ` (${detail})` : ''}`,
      res.status,
      body.error.code,
      body.error.message,
    );
  }
  return body.result;
}

// ---------------------------------------------------------------------
// Network — endpoint/network inventory, scan tasks, custom groups.
// ---------------------------------------------------------------------

/** getEndpointsList — the list of endpoints (managed and unmanaged), optionally scoped to a group and filtered. */
export async function getEndpointsList(
  creds: BitdefenderCredentials,
  params: GetEndpointsListParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'network', 'getEndpointsList', { ...params });
}

/** getManagedEndpointDetails — full detail (agent, protection modules, scan status) for one managed endpoint. */
export async function getManagedEndpointDetails(
  creds: BitdefenderCredentials,
  { endpointId }: GetManagedEndpointDetailsParams,
): Promise<Record<string, unknown>> {
  return jsonRpcCall(creds, 'network', 'getManagedEndpointDetails', { endpointId });
}

/** getCustomGroupsList — the child groups under a given group in the Network Inventory tree. */
export async function getCustomGroupsList(
  creds: BitdefenderCredentials,
  params: GetCustomGroupsListParams = {},
): Promise<Array<{ id: string; name: string }>> {
  return jsonRpcCall(creds, 'network', 'getCustomGroupsList', { ...params });
}

/** getNetworkInventoryItems — network inventory items (groups, computers, VMs, EC2 instances), optionally scoped and filtered. */
export async function getNetworkInventoryItems(
  creds: BitdefenderCredentials,
  params: GetNetworkInventoryItemsParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'network', 'getNetworkInventoryItems', { ...params });
}

/** getScanTasksList — previously created on-demand scan tasks and their status. */
export async function getScanTasksList(
  creds: BitdefenderCredentials,
  params: GetScanTasksListParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'network', 'getScanTasksList', { ...params });
}

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------

/** getPoliciesList — the list of security policies available to the account. */
export async function getPoliciesList(
  creds: BitdefenderCredentials,
  params: GetPoliciesListParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'policies', 'getPoliciesList', { ...params });
}

/** getPolicyDetails — full settings for one security policy. */
export async function getPolicyDetails(
  creds: BitdefenderCredentials,
  { policyId }: GetPolicyDetailsParams,
): Promise<Record<string, unknown>> {
  return jsonRpcCall(creds, 'policies', 'getPolicyDetails', { policyId });
}

// ---------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------

/** getBlocklistItems — file hashes present in the account's Blocklist (source: incident, import, or manual). */
export async function getBlocklistItems(
  creds: BitdefenderCredentials,
  params: GetBlocklistItemsParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'incidents', 'getBlocklistItems', { ...params });
}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

/** getReportsList — scheduled/instant reports configured on the account. */
export async function getReportsList(
  creds: BitdefenderCredentials,
  params: GetReportsListParams = {},
): Promise<BitdefenderPagedResponse> {
  return jsonRpcCall(creds, 'reports', 'getReportsList', { ...params });
}

/** getDownloadLinks — whether a report is ready, and the (Basic-auth-protected) URLs to download it. */
export async function getDownloadLinks(
  creds: BitdefenderCredentials,
  { reportId }: GetDownloadLinksParams,
): Promise<Record<string, unknown>> {
  return jsonRpcCall(creds, 'reports', 'getDownloadLinks', { reportId });
}
