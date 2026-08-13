/**
 * Shared interpretation of the Lex "child directed" data privacy declaration
 * across CloudFormation and Terraform inputs.
 */

const CONDITIONAL_KEY = 'Fn::If';

/** Resolves the declaration to a boolean, or undefined when absent/unresolvable. */
export function parseChildDirected(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return undefined;
}

/**
 * True when the declaration's real value cannot be determined at analysis time
 * AND it could still turn out to be true, for example an unresolved intrinsic
 * function or a plan-time unknown. A selection whose every branch is definitively
 * non-true is treated as resolved (and therefore reportable).
 */
export function isChildDirectedUnresolvable(value: unknown): boolean {
  if (value === null) return true;
  if (typeof value !== 'object') return false;
  return couldBeTrue(value);
}

function couldBeTrue(value: unknown): boolean {
  const branches = conditionalBranches(value);
  if (branches) return branches.some(couldBeTrue);
  if (value !== null && typeof value === 'object') return true;
  return parseChildDirected(value) === true;
}

function conditionalBranches(value: unknown): unknown[] | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const conditional = (value as Record<string, unknown>)[CONDITIONAL_KEY];
  if (!Array.isArray(conditional)) return undefined;
  return conditional.slice(1);
}
