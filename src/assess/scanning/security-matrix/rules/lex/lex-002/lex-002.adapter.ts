import { ControlAdapter } from '../../../controls/types.js';

export const DEFAULT_OBFUSCATION = 'DefaultObfuscation';

/** The only obfuscation type that leaves slot values unmasked. */
export const NONE_OBFUSCATION = 'None';

/** Any other type instructs Lex V2 to obscure the slot value, so it is compliant. */
export function isObfuscationDisabledType(type: unknown): boolean {
  if (type === undefined || type === null) return true;
  return typeof type === 'string' && type.trim().toLowerCase() === NONE_OBFUSCATION.toLowerCase();
}

export interface Lex002Adapter extends ControlAdapter {
  /** Names of slots whose value obfuscation is explicitly disabled. */
  findSlotsWithoutObfuscation(): string[];
}
