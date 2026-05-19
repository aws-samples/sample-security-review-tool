import { SecurityControl } from '../../../../../../src/assess/scanning/security-matrix/controls/security-control.js';
import { ControlFinding } from '../../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Svc__Adapter } from '../adapters/__svc__.adapter.js';

export class __Rule__Control extends SecurityControl<__Svc__Adapter> {
  constructor() {
    super({
      id: '__RULE_ID__',
      priority: 'HIGH',
      description: '__DESCRIPTION__',
      remediationScenarios: [],
    });
  }

  protected evaluate(adapter: __Svc__Adapter): ControlFinding | null {
    return null;
  }
}

export const __rule__Control = new __Rule__Control();
