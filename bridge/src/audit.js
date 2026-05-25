import * as fs from 'fs';
import * as nodePath from 'path';
// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------
export class AuditAppendError extends Error {
    cause;
    constructor(message, cause) {
        super(message);
        this.cause = cause;
        this.name = 'AuditAppendError';
    }
}
// ---------------------------------------------------------------------------
// appendAudit
// ---------------------------------------------------------------------------
export function appendAudit(path, event, opts) {
    // Ensure parent directory exists with mode 0o700
    fs.mkdirSync(nodePath.dirname(path), { recursive: true, mode: 0o700 });
    const line = JSON.stringify(event) + '\n';
    try {
        fs.appendFileSync(path, line, { encoding: 'utf8', mode: 0o600 });
    }
    catch (err) {
        if (opts.bestEffort === true) {
            const msg = err instanceof Error ? err.message : String(err);
            process.stderr.write(`[audit] append failed: ${msg}\n`);
            return;
        }
        throw new AuditAppendError('audit append failed', err);
    }
}
// ---------------------------------------------------------------------------
// redactParams
// ---------------------------------------------------------------------------
export function redactParams(params, specs) {
    const result = {};
    for (const key of Object.keys(params)) {
        if (specs[key]?.secret === true) {
            result[key] = '[REDACTED]';
        }
        else {
            result[key] = params[key];
        }
    }
    return result;
}
