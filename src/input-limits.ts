/**
 * Request / tool-input size limits.
 *
 * Addresses CVE-2026-111768 (GHSA-46jr-4wx8-v453, memory exhaustion during
 * input validation) and GHSA-f897-62hf-6gxq (no request body / batch cap).
 * Tracking: Linear WYREAI-454.
 *
 * The SDK's McpServer exposes `maxToolInputElements`, but the low-level
 * Server does not, so tool handlers call these helpers before dispatching.
 * Dependency-free on purpose: copy verbatim to other fleet repos.
 */

export const MAX_REQUEST_BODY_BYTES = 256 * 1024;
export const MAX_TOOL_INPUT_ELEMENTS = 10_000;

/**
 * Count every array element and every own object key at every depth.
 * Iterative (explicit stack) so deep nesting cannot overflow the call stack,
 * and returns as soon as the running count exceeds `max`.
 *
 * @param value - The value to walk.
 * @param max - Early-exit threshold.
 * @returns The element count, or a value above `max` once exceeded.
 */
export function countToolInputElements(value: unknown, max: number): number {
  let count = 0;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || typeof current !== 'object') continue;
    if (Array.isArray(current)) {
      count += current.length;
      if (count > max) return count;
      for (const item of current) stack.push(item);
    } else {
      const keys = Object.keys(current);
      count += keys.length;
      if (count > max) return count;
      for (const key of keys) stack.push((current as Record<string, unknown>)[key]);
    }
  }
  return count;
}

/**
 * Whether the tool input holds more than `max` elements (array items plus object keys, at any depth).
 *
 * @param args - The caller-supplied tool arguments.
 * @param max - Element limit; defaults to MAX_TOOL_INPUT_ELEMENTS.
 * @returns True when the input exceeds the limit.
 */
export function toolInputTooLarge(args: unknown, max = MAX_TOOL_INPUT_ELEMENTS): boolean {
  return countToolInputElements(args, max) > max;
}

/**
 * Builds the MCP error result for oversized tool input. The message is fixed
 * and never echoes caller-controlled values such as the tool name (CWE-209).
 *
 * @param max - Element limit reported in the message; defaults to MAX_TOOL_INPUT_ELEMENTS.
 * @returns A tool result with `isError: true`.
 */
export function toolInputTooLargeResult(max = MAX_TOOL_INPUT_ELEMENTS) {
  return {
    content: [
      {
        type: 'text' as const,
        text: `Tool input exceeds the maximum of ${max} elements`,
      },
    ],
    isError: true,
  };
}
