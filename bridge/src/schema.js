import { z } from 'zod';
// ---------------------------------------------------------------------------
// specToZod — convert a single ParamSpec to a Zod validator
// ---------------------------------------------------------------------------
export function specToZod(spec) {
    let s;
    if (spec.type === 'string') {
        let str = z.string();
        if (spec.pattern !== undefined) {
            str = str.regex(new RegExp(spec.pattern));
        }
        // enum wins over pattern — hard whitelist
        if (spec.enum !== undefined) {
            str = z.enum(spec.enum);
        }
        s = str;
    }
    else {
        // integer
        let n = z.number().int();
        if (spec.minimum !== undefined) {
            n = n.min(spec.minimum);
        }
        // Phase 1 lint guarantees maximum is present for integer params
        n = n.max(spec.maximum);
        s = n;
    }
    // Apply default last
    if (spec.default !== undefined) {
        s = s.default(spec.default);
    }
    // Apply description
    if (spec.description !== undefined) {
        s = s.describe(spec.description);
    }
    return s;
}
// ---------------------------------------------------------------------------
// buildShape — convert a params map to a strict Zod object schema
// ---------------------------------------------------------------------------
export function buildShape(params) {
    const shape = {};
    for (const [key, spec] of Object.entries(params)) {
        shape[key] = specToZod(spec);
    }
    return z.object(shape).strict();
}
