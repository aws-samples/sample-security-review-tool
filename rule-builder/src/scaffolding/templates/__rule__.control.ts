import { SecurityControl } from '../../../../src/assess/scanning/security-matrix/controls/security-control.js';
import { ControlFinding } from '../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Rule__Adapter } from './__safe-rule-id__.adapter.js';

export class __Rule__Control extends SecurityControl<__Rule__Adapter> {
  constructor() {
    super({
      id: '__RULE_ID__',
      priority: 'HIGH',
      description: '__DESCRIPTION__',
      remediationScenarios: [],
    });
  }

  protected evaluate(adapter: __Rule__Adapter): ControlFinding | null {
    return null;
  }
}

export const __rule__Control = new __Rule__Control();
