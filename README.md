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

Copy [`.env.example`](.env.example) and set the variables below.

| Env var | Required | Description |
|---|---|---|
| `BITDEFENDER_API_KEY` | For stdio and `AUTH_MODE=env` | API key generated in Control Center, with the Network/Policies/Reports/Incidents areas selected. |
| `BITDEFENDER_ACCESS_URL` | For stdio and `AUTH_MODE=env` | The account's Control Center Access URL (e.g. `https://cloud.gravityzone.bitdefender.com`). |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http`. |
| `AUTH_MODE` | No | `env` (default, reads the two vars above) or `gateway` (Docker image and Compose default). Gateway mode requires `X-Bitdefender-Api-Key` and `X-Bitdefender-Access-Url` on each `/mcp` request and never falls back to `BITDEFENDER_*`. |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service secret. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `replace-with-a-real-secret`, and similar copied examples). Compose will not start without it. Never commit a real value. Generate one with `openssl rand -hex 32`. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` is ignored in that mode. A known placeholder secret is still rejected. |
| `MCP_HTTP_HOST` | No | Bind address when `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` is set. Defaults to `127.0.0.1`. The container image sets `0.0.0.0`. Without a secret, the listener is `127.0.0.1`. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |
| `LOG_LEVEL` | No | `debug` \| `info` (default) \| `warn` \| `error`. |

`/health` stays unauthenticated and does not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### HTTP authentication

With `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` set, every `/mcp` request must include `X-Gateway-S2S`. A missing or invalid header returns 401 before vendor credentials are read.

The header is an HMAC the gateway signs with this container's `CONDUIT_S2S_SECRET`:

```text
X-Gateway-S2S: t=<unix seconds>,v1=<lowercase hex HMAC-SHA256>
```

The MAC is HMAC-SHA256 over the ASCII string `t=<unix seconds>` (the same `t=` prefix that begins the header), keyed with `CONDUIT_S2S_SECRET`. Timestamps more than 300 seconds from the server clock are rejected. The secret is never written to logs.

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Bitdefender-Api-Key` and `X-Bitdefender-Access-Url`. Those headers are the only credential source for that request. A request missing either one returns 401 and does not fall back to `BITDEFENDER_API_KEY` / `BITDEFENDER_ACCESS_URL`.

```typescript
// Gateway injects credentials and the X-Gateway-S2S proof
const response = await fetch('http://127.0.0.1:8080/mcp', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'x-gateway-s2s': 't=<unix seconds>,v1=<hex hmac-sha256>',
    'x-bitdefender-api-key': '<api key>',
    'x-bitdefender-access-url': 'https://cloud.gravityzone.bitdefender.com',
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
});
```

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

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass the S2S secret. In gateway mode, Bitdefender credentials arrive on each request as headers; they are not read from the environment.

```bash
docker build -t bitdefender-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  bitdefender-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, defaults `AUTH_MODE` to `gateway`, publishes `127.0.0.1:8080:8080`, and does not set `BITDEFENDER_API_KEY` or `BITDEFENDER_ACCESS_URL`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `BITDEFENDER_API_KEY` and `BITDEFENDER_ACCESS_URL`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e BITDEFENDER_API_KEY=your-api-key \
  -e BITDEFENDER_ACCESS_URL=https://cloud.gravityzone.bitdefender.com \
  -p 127.0.0.1:8080:8080 \
  bitdefender-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` only and logs a warning:

```bash
MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```
