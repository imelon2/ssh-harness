import { z } from 'zod';
import { buildShape } from './schema.js';
import { type Registry } from './allowlist.js';
import { type RuntimeConfig } from './config.js';
import { executeRuleCall } from './server.js';

/** MCP tool behavior hints (spec: ToolAnnotations). Advisory metadata for clients. */
export type ToolAnnotations = {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
};

export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  /** Machine-readable result conforming to the tool's outputSchema (when declared). */
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

export type Tool = {
  name: string;
  description: string;
  /** Zod object schema for the tool's input. McpServer.registerTool consumes this directly. */
  paramsSchema: z.ZodObject<Record<string, z.ZodTypeAny>>;
  /** Raw Zod shape for the tool's structured output. Enables structuredContent. */
  outputSchema?: z.ZodRawShape;
  annotations?: ToolAnnotations;
  handler: (args: unknown) => Promise<ToolResult>;
};

/**
 * Structured-output shape shared by every rule-derived tool. Mirrors the JSON
 * body returned by executeRuleCall so clients can parse results without
 * re-parsing a JSON string embedded in text content.
 */
export const EXEC_OUTPUT_SHAPE: z.ZodRawShape = {
  host: z.string(),
  exitCode: z.number().int().nullable(),
  durationMs: z.number(),
  timedOut: z.boolean(),
  truncated: z.object({ stdout: z.boolean(), stderr: z.boolean() }),
  stdout: z.string(),
  stderr: z.string(),
};

/**
 * Every rule-derived tool runs one read-only, allowlisted command against an
 * external host. Hence: read-only, non-destructive, idempotent (re-running a
 * read does not change state), open-world (reaches systems outside the server).
 */
const RULE_TOOL_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

/**
 * Build the static catalog of MCP tools from the rule registry.
 * One Tool per rule. Each handler captures only the ruleId (string), so the
 * registry can be swapped later for hot-reload without rebuilding closures.
 */
export function buildTools(registry: Registry, config: RuntimeConfig): Tool[] {
  const tools: Tool[] = [];
  for (const rule of registry.list()) {
    const ruleId = rule.id;
    const paramsSchema = buildShape(rule.params);

    tools.push({
      name: rule.tool.name,
      description: rule.tool.description,
      paramsSchema,
      outputSchema: EXEC_OUTPUT_SHAPE,
      annotations: { title: rule.tool.name, ...RULE_TOOL_ANNOTATIONS },
      handler: async (args: unknown) => {
        return executeRuleCall(registry, ruleId, (args ?? {}) as Record<string, unknown>, config);
      },
    });
  }
  return tools;
}
