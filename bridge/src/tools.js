import { buildShape } from './schema.js';
import { executeRuleCall } from './server.js';
/**
 * Build the static catalog of MCP tools from the rule registry.
 * One Tool per rule. Each handler captures only the ruleId (string), so the
 * registry can be swapped later for hot-reload without rebuilding closures.
 */
export function buildTools(registry, config) {
    const tools = [];
    for (const rule of registry.list()) {
        const ruleId = rule.id;
        const paramsSchema = buildShape(rule.params);
        tools.push({
            name: rule.tool.name,
            description: rule.tool.description,
            paramsSchema,
            handler: async (args) => {
                return executeRuleCall(registry, ruleId, (args ?? {}), config);
            },
        });
    }
    return tools;
}
