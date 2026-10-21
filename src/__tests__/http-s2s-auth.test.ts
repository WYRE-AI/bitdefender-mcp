/**
 * HTTP transport fail-closed S2S auth (CWE-306, WYREAI-454).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1
 * (loopback only). Known placeholders never count. /mcp rejects a missing or
 * invalid X-Gateway-S2S header; /health stays unauthenticated.
 */

import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { startHttpServer } from '../http.js';

const S2S_SECRET = 's2s-do-not-log-7f3a';

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
] as const;

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'BITDEFENDER_API_KEY',
  'LOG_LEVEL',
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string): string {
  const message = `t=${Math.floor(Date.now() / 1000)}`;
  return `${message},v1=${createHmac('sha256', secret).update(message).digest('hex')}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return { text: () => lines.join('\n'), restore: () => spy.mockRestore() };
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: string }> {
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
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error(`timeout ${options.method} ${options.path}`)));
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function listen(): Promise<{ port: number; address: string }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === 'string') throw new Error('HTTP server did not bind a TCP port');
  return { port: bound.port, address: bound.address };
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const initializeCall = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 'test', version: '0.0.0' },
  },
});

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.LOG_LEVEL = 'info';
  process.env.AUTH_MODE = 'env';
  process.env.BITDEFENDER_API_KEY = 'k';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop();
    if (server?.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe('HTTP startup', () => {
  it('rejects when CONDUIT_S2S_SECRET is empty', async () => {
    await expect(startHttpServer()).rejects.toThrow(/CONDUIT_S2S_SECRET is empty/);
  });

  it('rejects when the secret is whitespace and MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    await expect(startHttpServer()).rejects.toThrow(/Refusing to start HTTP transport/);
  });

  it.each(PLACEHOLDERS)('rejects known placeholder %j even with the dev flag', async (placeholder) => {
    const configured = `  ${placeholder.toUpperCase()}  `;
    process.env.CONDUIT_S2S_SECRET = configured;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const logs = captureStderr();
    try {
      const err = await startHttpServer().then(
        () => null,
        (e: Error) => e,
      );
      expect(err?.message).toContain('known placeholder');
      expect(err?.message).not.toContain(configured);
      expect(logs.text()).not.toContain(configured);
    } finally {
      logs.restore();
    }
  });

  it('starts on loopback with a warning when MCP_ALLOW_INSECURE_DEV=1 and /mcp is not S2S-gated', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    delete process.env.MCP_HTTP_HOST;
    const logs = captureStderr();
    try {
      const { port, address } = await listen();
      expect(address).toBe('127.0.0.1');
      expect(logs.text()).toContain('SECURITY WARNING');
      expect(logs.text()).toContain('MCP_ALLOW_INSECURE_DEV');

      const res = await sendHttp({
        port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders(),
        body: initializeCall,
      });
      expect(res.status).toBe(200);
    } finally {
      logs.restore();
    }
  });

  it.each(['0.0.0.0', '10.1.2.3'])(
    'rejects insecure dev with non-loopback MCP_HTTP_HOST=%s',
    async (host) => {
      process.env.MCP_ALLOW_INSECURE_DEV = '1';
      process.env.MCP_HTTP_HOST = host;
      await expect(startHttpServer()).rejects.toThrow(/loopback/);
    },
  );

  it('accepts localhost as the insecure-dev host and binds 127.0.0.1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = 'localhost';
    const logs = captureStderr();
    try {
      expect((await listen()).address).toBe('127.0.0.1');
    } finally {
      logs.restore();
    }
  });

  it('binds 0.0.0.0 when a secret is set and MCP_HTTP_HOST is unset', async () => {
    delete process.env.MCP_HTTP_HOST;
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    expect((await listen()).address).toBe('0.0.0.0');
  });
});

describe('HTTP /mcp authentication', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
  });

  it('returns 401 for a missing or invalid S2S header and never logs the secret', async () => {
    const logs = captureStderr();
    try {
      const { port } = await listen();
      const missing = await sendHttp({
        port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders(),
        body: initializeCall,
      });
      const invalid = await sendHttp({
        port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader('wrong-secret') }),
        body: initializeCall,
      });
      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain('X-Gateway-S2S');
      expect(logs.text()).not.toContain(S2S_SECRET);
    } finally {
      logs.restore();
    }
  });

  it('passes with a valid S2S header', async () => {
    const { port } = await listen();
    const res = await sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) }),
      body: initializeCall,
    });
    expect(res.status).toBe(200);
    expect(res.body).not.toContain(S2S_SECRET);
  });

  it('serves /health without authentication', async () => {
    const { port } = await listen();
    const res = await sendHttp({ port, method: 'GET', path: '/health' });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).status).toBe('ok');
    expect(res.body).not.toContain(S2S_SECRET);
  });
});
