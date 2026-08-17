import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { As001Adapter, CooldownState } from './as-001.adapter.js';

const ZERO_COOLDOWN_FINDING = 'zero-cooldown';
const NEGATIVE_COOLDOWN_FINDING = 'negative-cooldown';
const EMPTY_COOLDOWN_FINDING = 'empty-cooldown';
const NON_NUMERIC_COOLDOWN_FINDING = 'non-numeric-cooldown';

const FINDINGS = {
  [ZERO_COOLDOWN_FINDING]: {
    issue: 'Auto Scaling group disables the default cooldown period by setting it to zero seconds',
    remediation: 'Set the Auto Scaling group default cooldown period to a nonzero number of seconds so scaling activities are spaced apart.',
  },
  [NEGATIVE_COOLDOWN_FINDING]: {
    issue: 'Auto Scaling group sets a negative default cooldown period, which is not a valid duration and leaves the group with no effective cooldown',
    remediation: 'Replace the negative Auto Scaling group default cooldown with a positive number of seconds so scaling activities are spaced apart.',
  },
  [EMPTY_COOLDOWN_FINDING]: {
    issue: 'Auto Scaling group declares a default cooldown period with an empty text value, so no usable number of seconds is configured',
    remediation: 'Replace the empty Auto Scaling group default cooldown with an explicit positive number of seconds so scaling activities are spaced apart.',
  },
  [NON_NUMERIC_COOLDOWN_FINDING]: {
    issue: 'Auto Scaling group declares a default cooldown period as text that is not a number of seconds, so no valid cooldown is configured',
    remediation: 'Replace the non-numeric Auto Scaling group default cooldown with a positive whole number of seconds so scaling activities are spaced apart.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

const FINDING_BY_COOLDOWN_STATE: Partial<Record<CooldownState, FindingKey>> = {
  zero: ZERO_COOLDOWN_FINDING,
  negative: NEGATIVE_COOLDOWN_FINDING,
  empty: EMPTY_COOLDOWN_FINDING,
  'non-numeric': NON_NUMERIC_COOLDOWN_FINDING,
};

export class As001Control extends SecurityControl<As001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'AS-001',
      priority: 'HIGH',
      description: 'Auto Scaling Groups must have a default cooldown period configured (set to a nonzero value)',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: As001Adapter): FindingKey | null {
    return FINDING_BY_COOLDOWN_STATE[adapter.cooldownState] ?? null;
  }
}

export const as001Control = new As001Control();
