import { describe, it, expect } from 'vitest';
import { specToZod, buildShape } from '../src/schema.js';

describe('specToZod / buildShape', () => {
  it('1. string enum — accepts valid, rejects invalid', () => {
    const schema = specToZod({ type: 'string', enum: ['a', 'b'] });
    expect(schema.parse('a')).toBe('a');
    expect(schema.safeParse('c').success).toBe(false);
  });

  it('2. string pattern — accepts match, rejects non-match', () => {
    const schema = specToZod({ type: 'string', pattern: '^x' });
    expect(schema.parse('xyz')).toBe('xyz');
    expect(schema.safeParse('abc').success).toBe(false);
  });

  it('3. integer range — accepts in-range, rejects out-of-range and non-integer types', () => {
    const schema = specToZod({ type: 'integer', minimum: 1, maximum: 10 });
    expect(schema.parse(5)).toBe(5);
    expect(schema.safeParse(0).success).toBe(false);
    expect(schema.safeParse(11).success).toBe(false);
    expect(schema.safeParse('5').success).toBe(false);
  });

  it('4. default applied — missing key gets default value', () => {
    const shape = buildShape({ n: { type: 'integer', default: 200, maximum: 1000 } });
    expect(shape.parse({})).toEqual({ n: 200 });
  });

  it('5. enum wins over pattern — only enum values accepted', () => {
    const schema = specToZod({ type: 'string', enum: ['a'], pattern: 'X' });
    expect(schema.parse('a')).toBe('a');
    expect(schema.safeParse('X').success).toBe(false);
  });

  it('6. C-1 adversarial integer — value above maximum is rejected', () => {
    const schema = specToZod({ type: 'integer', maximum: 1000 });
    expect(schema.safeParse(999999999).success).toBe(false);
  });

  it('7. strict rejects extra properties', () => {
    const shape = buildShape({ a: { type: 'integer', maximum: 10 } });
    expect(shape.safeParse({ a: 1, b: 2 }).success).toBe(false);
  });
});
