import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { getCredentials, runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { MAX_REQUEST_BODY_BYTES } from './input-limits.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

// Conduit service-to-service auth, fail closed (CWE-306, WYREAI-454). HTTP
// startup refuses an empty CONDUIT_S2S_SECRET or a known placeholder unless
// MCP_ALLOW_INSECURE_DEV=1 (placeholders never qualify). That bypass skips
// X-Gateway-S2S and is loopback-only. A configured secret is always enforced.
// The secret value is never logged. See src/s2s-verify.ts.

/** Public example values. A copied placeholder must not verify as a real secret. */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  'replace-with-a-real-secret',
  'your-s2s-secret',
  'your-secret',
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'example',
  'replace-me',
  's2s-secret',
]);

const LOOPBACK_HOST = '127.0.0.1';

const MISSING_S2S_SECRET_ERROR =
  'Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. ' +
  'Set CONDUIT_S2S_SECRET, or set MCP_ALLOW_INSECURE_DEV=1 for local development only.';

const PLACEHOLDER_S2S_SECRET_ERROR =
  'Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. ' +
  'Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value. ' +
  'MCP_ALLOW_INSECURE_DEV does not bypass a placeholder secret.';

const NON_LOOPBACK_INSECURE_ERROR =
  'Refusing to start HTTP transport: MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET ' +
  'only permits a loopback MCP_HTTP_HOST (127.0.0.1, localhost, ::1).';

const INSECURE_DEV_WARNING =
  'SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. ' +
  'HTTP /mcp is not enforcing X-Gateway-S2S and is limited to loopback (127.0.0.1). ' +
  'Do not use this outside local development.';

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, '$1');
  return normalized === '127.0.0.1' || normalized === 'localhost' || normalized === '::1';
}

/** Refuse by throwing so startHttpServer rejects; the CLI entry logs and exits 1. */
function refuseStart(message: string): never {
  throw new Error(message);
}

/**
 * Secret for X-Gateway-S2S on /mcp, read at startup (not import). Empty is
 * fail-closed unless MCP_ALLOW_INSECURE_DEV=1; a placeholder always refuses.
 */
function resolveS2sSecret(): string {
  const secret = (process.env.CONDUIT_S2S_SECRET ?? '').trim();
  if (secret && KNOWN_PLACEHOLDER_SECRETS.has(secret.toLowerCase())) {
    refuseStart(PLACEHOLDER_S2S_SECRET_ERROR);
  }
  if (secret) return secret;
  if (process.env.MCP_ALLOW_INSECURE_DEV === '1') return '';
  return refuseStart(MISSING_S2S_SECRET_ERROR);
}

/**
 * Insecure dev (no secret) binds 127.0.0.1 and rejects a non-loopback
 * MCP_HTTP_HOST. A configured secret honors MCP_HTTP_HOST (default 0.0.0.0).
 */
function resolveListenHost(s2sSecret: string): string {
  const configured = (process.env.MCP_HTTP_HOST ?? '').trim();
  if (s2sSecret) return configured || '0.0.0.0';
  if (configured && !isLoopbackHost(configured)) refuseStart(NON_LOOPBACK_INSECURE_ERROR);
  return LOOPBACK_HOST;
}

export async function startHttpServer(): Promise<HttpServer> {
  const S2S_SECRET = resolveS2sSecret();
  const host = resolveListenHost(S2S_SECRET);
  // error level so LOG_LEVEL cannot hide the bypass.
  if (!S2S_SECRET) logger.error(INSECURE_DEV_WARNING);
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/health') {
      // /health is container LIVENESS, not credential-readiness. In gateway
      // mode, credentials arrive per-request via X-Bitdefender-Api-Key /
      // X-Bitdefender-Access-Url, not at startup - checking getCredentials()
      // here would 503 the container permanently regardless of whether any
      // customer has connected yet.
      const creds = getCredentials();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          credentials: { configured: !!creds },
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
      return;
    }

    // Empty S2S_SECRET is only reachable with MCP_ALLOW_INSECURE_DEV=1.
    if (S2S_SECRET && !verifyS2sHeader(req.headers[S2S_HEADER] as string | undefined, S2S_SECRET)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
        })
      );
      return;
    }

    // Body cap runs only after S2S passes so unauthenticated callers still get 401.
    const contentLength = Number(req.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32600, message: `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes` },
          id: null,
        })
      );
      return;
    }

    const apiKey = isGatewayMode ? (req.headers['x-bitdefender-api-key'] as string | undefined) : undefined;
    const accessUrl = isGatewayMode ? (req.headers['x-bitdefender-access-url'] as string | undefined) : undefined;

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true).
      // Per-request tenant credentials are carried in an AsyncLocalStorage
      // context opened by runWithCredentials() below. A stateless
      // request->single-response flow keeps the tool call inside that
      // context - switching to a stateful/SSE transport would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
        maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (apiKey && accessUrl) {
      await runWithCredentials({ apiKey, accessUrl }, handle);
    } else {
      await handle();
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => {
      logger.info(`HTTP streaming server listening on ${host}:${port}`);
      resolve();
    });
  });

  return httpServer;
}

// Entry point. Vitest imports this module to call startHttpServer, so skip the
// CLI entrypoint there. `node dist/http.js` still starts HTTP or stdio.
if (process.env.VITEST !== 'true') {
  if (process.env.MCP_TRANSPORT === 'http') {
    startHttpServer().catch((error) => {
      logger.error('Fatal startup error', error);
      process.exit(1);
    });
  } else {
    await import('./index.js');
  }
}
