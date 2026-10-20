/**
 * HTTP transport fail-closed auth.
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholders are rejected even when that flag is set. The insecure-dev
 * bypass listens on 127.0.0.1 only. /mcp rejects a missing or invalid
 * X-Gateway-S2S header. AUTH_MODE=gateway rejects requests that omit vendor
 * credential headers and must not fall back to BITDEFENDER_* in process.env.
 */

import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { jsonRpcSuccessResponse } from './test-helpers.js';
import { startHttpTransport } from '../http.js';

const CANARY_API_KEY = 'canary-api-key-do-not-log';
const ENV_API_KEY = 'env-key-should-not-be-used';
const ENV_ACCESS_URL = 'https://env.example.invalid';
const S2S_SECRET = 's2s-do-not-log-7f3a';
const HEADER_API_KEY = 'header-api-key';
const HEADER_ACCESS_URL = 'https://cloud.gravityzone.bitdefender.com';

const PLACEHOLDERS = [
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
  'ChangeMe',
  '  changeme  ',
] as const;

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'BITDEFENDER_API_KEY',
  'BITDEFENDER_ACCESS_URL',
  'LOG_LEVEL',
  'MCP_TRANSPORT',
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

function silenceLogs(): { errors: string[] } {
  const errors: string[] = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errors.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return { errors };
}

function assertNoSecrets(logged: string, extra: string[] = []): void {
  expect(logged).not.toContain(CANARY_API_KEY);
  expect(logged).not.toContain(ENV_API_KEY);
  expect(logged).not.toContain(S2S_SECRET);
  expect(logged).not.toContain(HEADER_API_KEY);
  for (const value of extra) {
    expect(logged).not.toContain(value);
  }
}

/** Drop the static refusal text so a placeholder that is also a word in that text ("secret", "placeholder") is still detectable if echoed. */
function withoutStaticRefusal(logged: string): string {
  return logged
    .replaceAll('known placeholder', '')
    .replaceAll('a placeholder', '')
    .replaceAll('Generate a secret', '')
    .replaceAll('CONDUIT_S2S_SECRET', '');
}

function mcpHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const listEndpointsCall = {
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'bitdefender_list_endpoints', arguments: {} },
};

async function listenPort(server: Server): Promise<number> {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('expected the HTTP server to bind a TCP port');
  }
  return address.port;
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

beforeEach(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.LOG_LEVEL = 'info';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.BITDEFENDER_API_KEY;
  delete process.env.BITDEFENDER_ACCESS_URL;
  delete process.env.MCP_TRANSPORT;
  vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server) continue;
    await new Promise<void>((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe('HTTP startup', () => {
  it('refuses to start when CONDUIT_S2S_SECRET is unset', async () => {
    process.env.BITDEFENDER_API_KEY = CANARY_API_KEY;
    const { errors } = silenceLogs();

    await expect(startHttpTransport()).rejects.toThrow('process.exit:1');
    const logged = errors.join('\n');
    expect(logged).toContain('Refusing to start HTTP transport');
    expect(logged).toContain('CONDUIT_S2S_SECRET is empty');
    assertNoSecrets(logged);
  });

  it('refuses to start when CONDUIT_S2S_SECRET is empty or MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    const { errors } = silenceLogs();

    await expect(startHttpTransport()).rejects.toThrow('process.exit:1');
    expect(errors.join('\n')).toContain('Refusing to start HTTP transport');
    expect(errors.join('\n')).toContain('CONDUIT_S2S_SECRET is empty');
  });

  it.each(PLACEHOLDERS)('refuses the known placeholder %j and does not log it', async (placeholder) => {
    process.env.CONDUIT_S2S_SECRET = placeholder;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    const { errors } = silenceLogs();

    await expect(startHttpTransport()).rejects.toThrow('process.exit:1');
    const logged = errors.join('\n');
    expect(logged).toContain('known placeholder');
    expect(logged).toContain('Refusing to start HTTP transport');
    expect(withoutStaticRefusal(logged).toLowerCase()).not.toContain(placeholder.trim().toLowerCase());
    assertNoSecrets(logged);
  });

  it.each(PLACEHOLDERS)('refuses the placeholder %j even when MCP_ALLOW_INSECURE_DEV=1', async (placeholder) => {
    process.env.CONDUIT_S2S_SECRET = placeholder;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const { errors } = silenceLogs();

    await expect(startHttpTransport()).rejects.toThrow('process.exit:1');
    const logged = errors.join('\n');
    expect(logged).toContain('known placeholder');
    expect(withoutStaticRefusal(logged).toLowerCase()).not.toContain(placeholder.trim().toLowerCase());
  });

  it('starts with a loud warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.BITDEFENDER_API_KEY = CANARY_API_KEY;
    const { errors } = silenceLogs();

    const server = await startHttpTransport();
    servers.push(server);

    const logged = errors.join('\n');
    expect(logged).toContain('SECURITY WARNING');
    expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
    expect(logged).toContain('WITHOUT service-to-service authentication');
    expect(logged).toContain('127.0.0.1');
    assertNoSecrets(logged);
    expect(server.address()).toMatchObject({ address: '127.0.0.1' });
  });

  it.each(['0.0.0.0', '10.1.2.3'])(
    'forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is %s',
    async (host) => {
      delete process.env.CONDUIT_S2S_SECRET;
      process.env.MCP_ALLOW_INSECURE_DEV = '1';
      process.env.MCP_HTTP_HOST = host;
      const { errors } = silenceLogs();

      const server = await startHttpTransport();
      servers.push(server);

      const logged = errors.join('\n');
      expect(logged).toContain(`MCP_HTTP_HOST=${host} is not a loopback address`);
      expect(logged).toContain('Binding 127.0.0.1 only');
      assertNoSecrets(logged);
      expect(server.address()).toMatchObject({ address: '127.0.0.1' });
    },
  );

  it('honors a non-loopback MCP_HTTP_HOST when CONDUIT_S2S_SECRET is set', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    const { errors } = silenceLogs();

    const server = await startHttpTransport();
    servers.push(server);

    expect(errors.join('\n')).not.toContain('not a loopback address');
    expect(errors.join('\n')).not.toContain(S2S_SECRET);
    expect(server.address()).toMatchObject({ address: '0.0.0.0' });
  });

  it('defaults to 127.0.0.1 when a secret is set and MCP_HTTP_HOST is unset', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    silenceLogs();

    const server = await startHttpTransport();
    servers.push(server);

    expect(server.address()).toMatchObject({ address: '127.0.0.1' });
  });
});

describe('HTTP /mcp authentication', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.AUTH_MODE = 'gateway';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.BITDEFENDER_API_KEY = ENV_API_KEY;
    process.env.BITDEFENDER_ACCESS_URL = ENV_ACCESS_URL;
  });

  it('returns 401 when the S2S header is missing or invalid and does not log the secret', async () => {
    const { errors } = silenceLogs();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const server = await startHttpTransport();
    servers.push(server);
    const port = await listenPort(server);

    const missing = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-bitdefender-api-key': HEADER_API_KEY,
        'x-bitdefender-access-url': HEADER_ACCESS_URL,
      }),
      body: JSON.stringify(listEndpointsCall),
    });
    const missingBody = JSON.parse(missing.body) as { error?: string };

    const invalid = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader('wrong-secret'),
        'x-bitdefender-api-key': HEADER_API_KEY,
        'x-bitdefender-access-url': HEADER_ACCESS_URL,
      }),
      body: JSON.stringify(listEndpointsCall),
    });
    const invalidBody = JSON.parse(invalid.body) as { error?: string };

    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    expect(missingBody.error).toContain('X-Gateway-S2S');
    expect(invalidBody.error).toContain('X-Gateway-S2S');
    expect(missing.body).not.toContain(ENV_API_KEY);
    expect(missing.body).not.toContain(S2S_SECRET);
    expect(invalid.body).not.toContain(HEADER_API_KEY);
    assertNoSecrets(errors.join('\n'));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns 401 in gateway mode without credential headers and does not use env credentials', async () => {
    silenceLogs();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const server = await startHttpTransport();
    servers.push(server);
    const port = await listenPort(server);

    const response = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) }),
      body: JSON.stringify(listEndpointsCall),
    });
    const body = JSON.parse(response.body) as { error?: string };

    expect(response.status).toBe(401);
    expect(body.error).toContain('missing required gateway credential headers');
    expect(body.error).toContain('X-Bitdefender-Api-Key');
    expect(body.error).toContain('X-Bitdefender-Access-Url');
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(ENV_ACCESS_URL);
    expect(response.body).not.toContain(S2S_SECRET);
    expect(fetchMock).not.toHaveBeenCalled();

    const partial = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
        'x-bitdefender-api-key': HEADER_API_KEY,
      }),
      body: JSON.stringify(listEndpointsCall),
    });
    expect(partial.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus credential headers and uses those credentials', async () => {
    const { errors } = silenceLogs();
    const fetchMock = vi.fn().mockResolvedValue(
      jsonRpcSuccessResponse({ page: 1, pagesCount: 1, perPage: 30, total: 0, items: [] }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const server = await startHttpTransport();
    servers.push(server);
    const port = await listenPort(server);

    const response = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
        'x-bitdefender-api-key': HEADER_API_KEY,
        'x-bitdefender-access-url': HEADER_ACCESS_URL,
      }),
      body: JSON.stringify(listEndpointsCall),
    });

    expect(response.status).toBe(200);
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(ENV_ACCESS_URL);
    expect(response.body).not.toContain(S2S_SECRET);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${HEADER_ACCESS_URL}/v1.0/jsonrpc/network`);
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Basic ${Buffer.from(`${HEADER_API_KEY}:`).toString('base64')}`);
    expect(headers.Authorization).not.toBe(`Basic ${Buffer.from(`${ENV_API_KEY}:`).toString('base64')}`);
    assertNoSecrets(errors.join('\n'));
  });

  it('serves /health without authentication and without reading credentials', async () => {
    silenceLogs();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const server = await startHttpTransport();
    servers.push(server);
    const port = await listenPort(server);

    const response = await sendHttp({ port, method: 'GET', path: '/health' });
    const body = JSON.parse(response.body) as { status?: string; mode?: string };

    expect(response.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.mode).toBe('gateway');
    expect(body).not.toHaveProperty('credentials');
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(ENV_ACCESS_URL);
    expect(JSON.stringify(body)).not.toContain(S2S_SECRET);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
