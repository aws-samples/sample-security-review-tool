import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { As001Adapter, CooldownState } from './as-001.adapter.js';

const ZERO_COOLDOWN_SCENARIO = 'zero-cooldown';
const NEGATIVE_COOLDOWN_SCENARIO = 'negative-cooldown';
const EMPTY_COOLDOWN_SCENARIO = 'empty-cooldown';
const NON_NUMERIC_COOLDOWN_SCENARIO = 'non-numeric-cooldown';

const FINDINGS: Partial<Record<CooldownState, ControlFinding>> = {
  zero: {
    scenario: ZERO_COOLDOWN_SCENARIO,
    issue: 'Auto Scaling group disables the default cooldown period by setting it to zero seconds',
  },
  negative: {
    scenario: NEGATIVE_COOLDOWN_SCENARIO,
    issue:
      'Auto Scaling group sets a negative default cooldown period, which is not a valid duration and leaves the group with no effective cooldown',
  },
  empty: {
    scenario: EMPTY_COOLDOWN_SCENARIO,
    issue:
      'Auto Scaling group declares a default cooldown period with an empty text value, so no usable number of seconds is configured',
  },
  'non-numeric': {
    scenario: NON_NUMERIC_COOLDOWN_SCENARIO,
    issue:
      'Auto Scaling group declares a default cooldown period as text that is not a number of seconds, so no valid cooldown is configured',
  },
};

export class As001Control extends SecurityControl<As001Adapter> {
  constructor() {
    super({
      id: 'AS-001',
      priority: 'HIGH',
      description: 'Auto Scaling Groups must have a default cooldown period configured (set to a nonzero value)',
      remediationScenarios: [
        {
          scenario: ZERO_COOLDOWN_SCENARIO,
          intent:
            'Set the Auto Scaling group default cooldown period to a nonzero number of seconds so scaling activities are spaced apart.',
        },
        {
          scenario: NEGATIVE_COOLDOWN_SCENARIO,
          intent:
            'Replace the negative Auto Scaling group default cooldown with a positive number of seconds so scaling activities are spaced apart.',
        },
        {
          scenario: EMPTY_COOLDOWN_SCENARIO,
          intent:
            'Replace the empty Auto Scaling group default cooldown with an explicit positive number of seconds so scaling activities are spaced apart.',
        },
        {
          scenario: NON_NUMERIC_COOLDOWN_SCENARIO,
          intent:
            'Replace the non-numeric Auto Scaling group default cooldown with a positive whole number of seconds so scaling activities are spaced apart.',
        },
      ],
    });
  }

  protected evaluate(adapter: As001Adapter): ControlFinding | null {
    return FINDINGS[adapter.cooldownState] ?? null;
  }
}

export const as001Control = new As001Control();
