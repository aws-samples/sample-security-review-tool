import { ControlAdapter } from '../../../controls/types.js';

/** How the Auto Scaling group's default cooldown period is declared. */
export type CooldownState = 'absent' | 'zero' | 'negative' | 'nonzero' | 'empty' | 'non-numeric' | 'unknown';

export interface As001Adapter extends ControlAdapter {
  readonly cooldownState: CooldownState;
}
