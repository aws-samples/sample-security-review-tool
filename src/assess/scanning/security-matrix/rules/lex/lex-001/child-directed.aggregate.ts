import { isChildDirectedUnresolvable, parseChildDirected } from './child-directed.js';

export interface ChildDirectedVerdict {
  /** True only when every declaration resolves to true. */
  readonly value: boolean | undefined;
  /** True when no declaration is non-true and at least one cannot be resolved. */
  readonly unresolvable: boolean;
}

/**
 * A bot may declare several data privacy configurations. Child-directed protection is only
 * demonstrably enforced when every declaration resolves to true, so a single non-true
 * declaration decides the verdict.
 */
export function aggregateChildDirected(rawValues: readonly unknown[]): ChildDirectedVerdict {
  if (rawValues.length === 0) return { value: undefined, unresolvable: false };

  const declarations = rawValues.map(raw => ({
    value: parseChildDirected(raw),
    unresolvable: isChildDirectedUnresolvable(raw),
  }));

  if (declarations.some(d => !d.unresolvable && d.value !== true)) {
    return { value: false, unresolvable: false };
  }
  if (declarations.some(d => d.unresolvable)) {
    return { value: undefined, unresolvable: true };
  }
  return { value: true, unresolvable: false };
}
