import { z } from 'zod';
import { buildShape } from './schema.js';
import { type Registry } from './allowlist.js';
import { type RuntimeConfig } from './config.js';
import { executeRuleCall } from './server.js';

export type Tool = {
  name: string;
  description: string;
  /** Zod object schema for the tool's input. McpServer.registerTool consumes this directly. */
  paramsSchema: z.ZodObject<Record<string, z.ZodTypeAny>>;
  handler: (args: unknown) => Promise<{
    content: Array<{ type: 'text'; text: string }>;
    isError?: boolean;
  }>;
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
      handler: async (args: unknown) => {
        return executeRuleCall(registry, ruleId, (args ?? {}) as Record<string, unknown>, config);
      },
    });
  }
  return tools;
}
