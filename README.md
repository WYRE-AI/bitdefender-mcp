# Bitdefender GravityZone MCP Server

MCP server for [Bitdefender GravityZone](https://www.bitdefender.com/business/)'s Control Center API - endpoint/network inventory, security policies, the account-wide malware-hash Blocklist, and scheduled/instant reports - for AI assistants and the WYRE Conduit gateway.

> **New call shape for this catalog:** GravityZone's API is **JSON-RPC 2.0**, not REST - every other Conduit sidecar (Cork, CyberQP, Slide, UniFi, Cisco Duo) calls a conventional REST API. See [Authentication](#authentication) and [JSON-RPC shape](#json-rpc-shape) below.

## Authentication

GravityZone authenticates with **HTTP Basic Authentication** (RFC 2617): the API key is sent as the **username**, with an **empty password** - `Authorization: Basic base64(apiKey + ":")`. This is also a new shape for this catalog - every other static-key connector here (Cork, CyberQP, Slide, UniFi) sends a custom `X-Vendor-Api-Key` header that the sidecar turns into a Bearer token; GravityZone has no bearer-token concept at all.

API keys are generated in Control Center under **My Account -> API keys**, and each key is scoped, **at generation time**, to a checklist of API *areas* (Network, Policies, Reports, Incidents, Companies, Licensing, Accounts, Packages, Integrations, Push, Quarantine). This connector's key needs the **Network**, **Policies**, **Reports**, and **Incidents** areas selected - the other seven are never called and do not need to be enabled.

This connector also needs the account's **Control Center Access URL** (shown on that same My Account page, under **Control Center API**) - GravityZone Cloud, its EU region, and any self-hosted/on-premise Control Center each have a different API host, so unlike most vendors in this catalog there is no single fixed base URL to hardcode.

In gateway mode, both arrive per-request via the `X-Bitdefender-Api-Key` and `X-Bitdefender-Access-Url` headers; in local/stdio mode they're read once from `BITDEFENDER_API_KEY` and `BITDEFENDER_ACCESS_URL`.

### JSON-RPC shape

GravityZone exposes several **separate** JSON-RPC 2.0 endpoints, one per product area, at `<accessUrl>/v1.0/jsonrpc/<area>` (e.g. `/v1.0/jsonrpc/network`, `/v1.0/jsonrpc/policies`). Every call to a given area - whatever it does - is an HTTP `POST` to that same URL with an identical envelope:

```json
{ "id": "<uuid>", "jsonrpc": "2.0", "method": "getEndpointsList", "params": { "parentId": "..." } }
```

The operation lives entirely **inside the body** (`method` + `params`), never in the URL or HTTP verb - there is no GET/POST/PATCH/DELETE distinction to key a read-only boundary off of, unlike every REST sidecar in this catalog. This connector's read-only scope is therefore enforced by only ever calling documented `getXxx`/`listXxx` **method names** (see [Scope](#scope) below and `client.ts`'s `jsonRpcCall()`), not by restricting HTTP verbs.

A successful call returns `{ "id", "jsonrpc", "result": ... }`. A failed call can come back two ways, and this connector's `client.ts` distinguishes both:
- **HTTP-layer failure** - `401` (bad/missing key), `403` (the key doesn't have this API area enabled - see above), `405` (non-POST), or `429` (rate limit).
- **JSON-RPC-layer failure** - HTTP `200` with a body `error` member (`{code, message, data.details}`, e.g. `-32602 Invalid params`).

Rate limit: **10 requests/second per API key**; GravityZone returns `429` above that.

## Configuration

| Env var | Description |
|---|---|
| `BITDEFENDER_API_KEY` | API key generated in Control Center, with the Network/Policies/Reports/Incidents areas selected. |
| `BITDEFENDER_ACCESS_URL` | The account's Control Center Access URL (e.g. `https://cloud.gravityzone.bitdefender.com`). |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the two vars above) or `gateway` (credentials arrive per-request via the `X-Bitdefender-Api-Key` / `X-Bitdefender-Access-Url` headers, injected by the Conduit gateway). |
| `CONDUIT_S2S_SECRET` | **Required for the HTTP transport.** Every `/mcp` request must carry a valid `X-Gateway-S2S` header (Conduit sidecar auth); `/health` stays unauthenticated. Generate with `openssl rand -hex 32`. Not used by stdio. |
| `MCP_ALLOW_INSECURE_DEV` | Set to `1` for local development only: lets the HTTP transport start without `CONDUIT_S2S_SECRET`, skips the S2S check, and is restricted to loopback (startup is refused if `MCP_HTTP_HOST` is non-loopback). Logs a `SECURITY WARNING`. Never bypasses a placeholder secret. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

### HTTP transport authentication (fail closed)

With `MCP_TRANSPORT=http`, the server **refuses to start** unless `CONDUIT_S2S_SECRET` is set to a real value (trimmed; known placeholders such as `changeme` or `replace-with-a-real-secret` are also refused). `startHttpServer` rejects and the CLI logs the error and exits 1. This matches the fleet fail-closed S2S pattern (CWE-306; conduit#2194, WYREAI-454). The secret is never logged.

```sh
export CONDUIT_S2S_SECRET="$(openssl rand -hex 32)"   # same value the Conduit gateway signs with
```

For local development only, `MCP_ALLOW_INSECURE_DEV=1` permits starting with no secret. In that mode `/mcp` is not S2S-gated, the server binds `127.0.0.1` only, and startup is refused if `MCP_HTTP_HOST` is set to a non-loopback address.

### Request limits

- HTTP request bodies are capped at 256 KiB (262144 bytes). After the `X-Gateway-S2S` check passes, a `Content-Length` above the cap returns 413 with a JSON-RPC error; bodies without `Content-Length` are capped by the MCP SDK transport. Unauthenticated requests still get 401 first.
- `tools/call` arguments are capped at 10,000 elements (every array item and object key at any depth). Larger inputs return an `isError` tool result and are never dispatched.

These limits address CVE-2026-111768 / GHSA-46jr-4wx8-v453 (memory exhaustion during validation) and GHSA-f897-62hf-6gxq (no request body / batch cap).

## Tools

### Network - endpoint/network inventory
- `bitdefender_list_endpoints` - list managed/unmanaged endpoints (name, FQDN, IP, MACs, group, agent flags), optionally scoped and filtered.
- `bitdefender_get_endpoint` - full detail for one managed endpoint (agent version, license status, scan/update status).
- `bitdefender_list_custom_groups` - list the child groups under a Network Inventory group.
- `bitdefender_list_network_inventory` - list inventory items (groups, computers, VMs, EC2 instances) with per-type filtering.
- `bitdefender_list_scan_tasks` - list previously created on-demand scan tasks and their status.

### Policies
- `bitdefender_list_policies` - list security policies available to the account.
- `bitdefender_get_policy` - get full settings for one security policy.

### Incidents
- `bitdefender_list_blocklist_items` - list file hashes present in the account's Blocklist.

### Reports
- `bitdefender_list_reports` - list scheduled/instant reports configured on the account.
- `bitdefender_get_report_download_links` - check download readiness and get a report's download URL(s).

## Scope

**This is a deliberately narrow, read-only v1 surface: exactly 10 of GravityZone's `getXxx`/`listXxx` methods across the Network, Policies, Incidents, and Reports APIs.** Every tool is classified `isAdmin: true` in the Conduit gateway - GravityZone is an endpoint-protection product, so every read this connector exposes (endpoint IP/MAC/hostname inventory, security policy settings, malware-hash blocklist entries, security posture reports) is security/PII-adjacent by construction. No mutating (`create`/`update`/`delete`/`move`/`set`/`add`/`remove`) method is implemented, by design, not by oversight:

**Hard-excluded (Network API) - never implemented:**
- `createCustomGroup`, `deleteCustomGroup`, `moveCustomGroup` - group provisioning/mutation.
- `moveEndpoints`, `deleteEndpoint` - endpoint mutation/removal.
- `createScanTask` - dispatches a real on-demand scan to a real managed endpoint. `bitdefender_list_scan_tasks` (read) stays; this does not.
- `setEndpointLabel` - endpoint mutation.

**Hard-excluded (Incidents API) - never implemented:**
- `addToBlocklist`, `removeFromBlocklist` - Blocklist mutation. `bitdefender_list_blocklist_items` (read) stays; these do not.
- `createIsolateEndpointTask`, `createRestoreEndpointFromIsolationTask` - genuine remote-response actions that isolate/restore a real managed endpoint from the network.

**Hard-excluded (Reports API) - never implemented:**
- `createReport` - creates a new scheduled/instant report definition.
- `deleteReport` - deletes a report definition.

**Out of scope entirely (not requested, not implemented):** the Companies, Licensing, Accounts, Packages, Integrations, Push, and Quarantine APIs. Quarantine in particular (`getQuarantineItemsList` and its `createRemove/Restore*QuarantineItemTask` write methods) was in Bitdefender's own catalog of API areas but outside this connector's requested scope (endpoint/network inventory, policies, incidents, reports); it can be added as a deliberate follow-up if there's demand, not by default.

They can be added as a follow-up if there's demand, after a deliberate scope decision - not by default.

### Credential scope

**Two-tier confidence split**, per this catalog's convention for a claim about what a credential can and cannot reach:

- **STRUCTURALLY VERIFIED** - this connector's own code never calls a mutating JSON-RPC method: confirmed against `client.ts`/`tools/*.ts`, only the 10 documented `getXxx`/`listXxx` methods listed under [Tools](#tools) are ever sent, no passthrough/arbitrary-method call exists anywhere in `src/`. This connector is read-only **by construction**.
- **VENDOR-DOCUMENTED, AND THE FINDING RUNS THE OTHER WAY** - GravityZone's own API-key generation UI (Control Center -> My Account -> API keys) only gates access **per API area** (Network/Policies/Reports/Incidents/...), confirmed against Bitdefender's official API Guide (Getting Started section 1.3, "API Keys": *"Each API key allows the application to call methods exposed by one or several APIs. The allowed APIs are selected at the time the API key is generated"*). There is **no documented per-method or read/write permission flag**. A key with the Network area enabled can call `getEndpointsList` (read) **and** `moveEndpoints`/`deleteEndpoint`/`createScanTask` (write) - the same area, the same permission checkbox, no finer-grained scoping exists on Bitdefender's side. **This connector's read-only posture is enforced entirely by its own code, not by any narrower credential scope GravityZone itself offers** - the same posture this catalog's other security-product connectors (Cork, CyberQP, Cisco Duo) already document for their own admin-tier classification, stated once here for the credential-scope question specifically.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

```bash
docker build -t bitdefender-mcp .
docker run -p 8080:8080 -e BITDEFENDER_API_KEY=... -e BITDEFENDER_ACCESS_URL=... bitdefender-mcp
```
