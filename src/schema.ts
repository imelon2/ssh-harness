import { z } from 'zod';
import type { ParamSpec } from './allowlist.js';

// ---------------------------------------------------------------------------
// specToZod — convert a single ParamSpec to a Zod validator
// ---------------------------------------------------------------------------

export function specToZod(spec: ParamSpec): z.ZodTypeAny {
  let s: z.ZodTypeAny;

  if (spec.type === 'string') {
    let str: z.ZodTypeAny = z.string();

    if (spec.pattern !== undefined) {
      // Fully anchor: Zod's .regex() uses RegExp.test() (substring match), so an
      // un-anchored pattern like "[a-z0-9]+" would accept any *superstring*
      // (e.g. "; rm -rf /") — silently defeating the author's whitelist intent.
      // Anchoring makes the pattern a true whole-value whitelist.
      str = (str as z.ZodString).regex(new RegExp('^(?:' + spec.pattern + ')$'));
    }

    // enum wins over pattern — hard whitelist
    if (spec.enum !== undefined) {
      str = z.enum(spec.enum as [string, ...string[]]);
    }

    s = str;
  } else {
    // integer
    let n = z.number().int();

    if (spec.minimum !== undefined) {
      n = n.min(spec.minimum);
    }

    // Phase 1 lint guarantees maximum is present for integer params
    n = n.max(spec.maximum!);

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

export function buildShape(
  params: Record<string, ParamSpec>,
): z.ZodObject<Record<string, z.ZodTypeAny>> {
  const shape: Record<string, z.ZodTypeAny> = {};

  for (const [key, spec] of Object.entries(params)) {
    shape[key] = specToZod(spec);
  }

  return z.object(shape).strict();
}
