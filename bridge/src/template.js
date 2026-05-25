// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class MissingPlaceholderError extends Error {
    key;
    constructor(key) {
        super(`missing placeholder: {${key}}`);
        this.key = key;
        this.name = 'MissingPlaceholderError';
    }
}
export class UnknownPlaceholderError extends Error {
    key;
    constructor(key) {
        super(`unknown placeholder: {${key}}`);
        this.key = key;
        this.name = 'UnknownPlaceholderError';
    }
}
// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------
const PLACEHOLDER_RE = /\{(\w+)\}/g;
function substitute(template, params) {
    return template.replace(PLACEHOLDER_RE, (_match, name) => {
        if (!(name in params)) {
            throw new MissingPlaceholderError(name);
        }
        return String(params[name]);
    });
}
export function renderArgv(rule, params) {
    const host = substitute(rule.template.host, params);
    const argv = rule.template.argv.map((entry) => substitute(entry, params));
    return { host, argv };
}
