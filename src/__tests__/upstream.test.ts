import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_UPSTREAM_BYTES_CEILING, MAX_UPSTREAM_BYTES_DEFAULT, maxUpstreamBytes } from '../upstream.js';

describe('maxUpstreamBytes', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it.each([undefined, '', '   ', 'garbage', '0', '-1', 'nope', 'Infinity', '1e7', '1.5', '16MiB', '9'.repeat(400)])(
    'uses the default for %s', (value) => {
      vi.stubEnv('BITDEFENDER_MAX_UPSTREAM_BYTES', value);
      expect(maxUpstreamBytes()).toBe(MAX_UPSTREAM_BYTES_DEFAULT);
    },
  );

  it('clamps values above the ceiling', () => {
    vi.stubEnv('BITDEFENDER_MAX_UPSTREAM_BYTES', String(MAX_UPSTREAM_BYTES_CEILING + 1));
    expect(maxUpstreamBytes()).toBe(MAX_UPSTREAM_BYTES_CEILING);
  });

  it('honours a trimmed positive integer', () => {
    vi.stubEnv('BITDEFENDER_MAX_UPSTREAM_BYTES', ' 1000 ');
    expect(maxUpstreamBytes()).toBe(1000);
  });
});
