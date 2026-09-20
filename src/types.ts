/**
 * Bitdefender GravityZone authenticates with HTTP Basic Authentication
 * (RFC 2617): the API key is sent as the username, with an EMPTY password -
 * `Authorization: Basic base64(apiKey + ":")`. This is a genuinely different
 * shape from every other static-key connector in this catalog (Cork/
 * CyberQP/Slide/UniFi all send a custom `X-Vendor-Api-Key` header that the
 * sidecar turns into `Authorization: Bearer <key>`) - see README's
 * Authentication section and client.ts's buildBasicAuthHeader().
 *
 * `accessUrl` is the customer's Control Center Access URL (shown under
 * My Account -> Control Center API - e.g.
 * https://cloud.gravityzone.bitdefender.com for GravityZone Cloud, or a
 * self-hosted/on-premise Control Center's own base URL). GravityZone has no
 * single fixed API host the way most vendors in this catalog do, so this
 * connector needs both fields, same shape as cisco-duo's apiHost.
 */
export interface BitdefenderCredentials {
  apiKey: string;
  accessUrl: string;
}

/** Thrown when GravityZone rejects the API key (HTTP 401 - missing/invalid key). */
export class BitdefenderAuthError extends Error {}

/**
 * Thrown on HTTP 403 - the API key authenticated, but the specific JSON-RPC
 * API area being called (network/policies/reports/incidents) was not
 * selected when the key was generated. See README's "Credential scope"
 * section: Bitdefender's key-generation UI gates access per API AREA, not
 * per method, so this is a coarser-grained failure than a bad key.
 */
export class BitdefenderForbiddenError extends Error {}

/** Thrown when GravityZone rate-limits the request (HTTP 429 - more than 10 req/s per key). */
export class BitdefenderRateLimitError extends Error {}

/**
 * Thrown for a JSON-RPC-level error (HTTP 200 with a body `error` member -
 * e.g. -32602 Invalid params) or any other unexpected HTTP status.
 * `rpcCode`/`rpcMessage` are populated when the failure came back as a
 * JSON-RPC error object rather than a raw HTTP failure.
 */
export class BitdefenderApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly rpcCode?: number,
    readonly rpcMessage?: string,
  ) {
    super(message);
  }
}

/**
 * The four JSON-RPC API areas this connector calls. Each is a SEPARATE
 * endpoint (`<accessUrl>/v1.0/jsonrpc/<area>`) with its own key-generation
 * permission flag - see client.ts's jsonRpcCall() and README's
 * Authentication section.
 */
export type BitdefenderApiArea = 'network' | 'policies' | 'reports' | 'incidents';

export interface PageParams {
  page?: number;
  perPage?: number;
}

// ---------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------

/** Sub-object of GetEndpointsListParams.filters - see "Available Filters" in GravityZone's API guide. */
export interface EndpointFilters {
  security?: {
    management?: {
      managedWithBest?: boolean;
      managedExchangeServers?: boolean;
      managedRelays?: boolean;
      securityServers?: boolean;
    };
  };
  depth?: {
    allItemsRecursively?: boolean;
  };
  details?: {
    ssid?: string;
    macs?: string[];
  };
}

/** Extra filter section available to getNetworkInventoryItems but not getEndpointsList. */
export interface NetworkInventoryFilters extends EndpointFilters {
  type?: {
    groups?: boolean;
    ec2Instances?: boolean;
    computers?: boolean;
    virtualMachines?: boolean;
  };
}

export interface GetEndpointsListParams extends PageParams {
  parentId?: string;
  isManaged?: boolean;
  filters?: EndpointFilters;
}

export interface GetManagedEndpointDetailsParams {
  endpointId: string;
}

export interface GetCustomGroupsListParams {
  parentId?: string;
}

export interface GetNetworkInventoryItemsParams extends PageParams {
  parentId?: string;
  filters?: NetworkInventoryFilters;
}

export interface GetScanTasksListParams extends PageParams {
  name?: string;
  status?: 1 | 2 | 3;
}

/** Shared paginated-list envelope returned by getEndpointsList, getNetworkInventoryItems, getScanTasksList, getPoliciesList, getReportsList, getBlocklistItems. */
export interface BitdefenderPagedResponse<T = unknown> {
  page?: number;
  pagesCount?: number;
  perPage?: number;
  total?: number;
  items: T[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------

export interface GetPoliciesListParams extends PageParams {}

export interface GetPolicyDetailsParams {
  policyId: string;
}

// ---------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------

export interface GetBlocklistItemsParams extends PageParams {}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

export interface GetReportsListParams extends PageParams {
  name?: string;
  type?: number;
}

export interface GetDownloadLinksParams {
  reportId: string;
}
