import { CooldownState } from './as-001.adapter.js';

/** Placeholder a deployment-time input with no supplied value resolves to. */
const UNSUPPLIED_INPUT_PLACEHOLDER = 'DEFAULT';

/**
 * Classifies a declared default cooldown value, whatever shape the IaC source presents it in.
 * Values the scanner cannot resolve (unresolved intrinsics, unsupplied inputs) are unknown.
 */
export function classifyCooldown(cooldown: unknown): CooldownState {
  if (cooldown === undefined || cooldown === null) return 'absent';
  if (typeof cooldown === 'number') return classifyNumber(cooldown);
  if (typeof cooldown === 'string') return classifyString(cooldown);
  return 'unknown';
}

function classifyString(cooldown: string): CooldownState {
  if (cooldown.trim().length === 0) return 'empty';
  if (cooldown === UNSUPPLIED_INPUT_PLACEHOLDER) return 'unknown';
  const parsed = Number(cooldown);
  if (!Number.isFinite(parsed)) return 'non-numeric';
  return classifyNumber(parsed);
}

function classifyNumber(cooldown: number): CooldownState {
  if (!Number.isFinite(cooldown)) return 'non-numeric';
  if (cooldown === 0) return 'zero';
  if (cooldown < 0) return 'negative';
  return 'nonzero';
}
