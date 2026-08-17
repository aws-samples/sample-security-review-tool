import { SecurityControl } from '../../../../src/assess/scanning/security-matrix/controls/security-control.js';
import type { Finding } from '../../../../src/assess/scanning/security-matrix/controls/types.js';
import type { __Rule__Adapter } from './__safe-rule-id__.adapter.js';

const FINDINGS = {} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class __Rule__Control extends SecurityControl<__Rule__Adapter, FindingKey> {
  constructor() {
    super({
      id: '__RULE_ID__',
      priority: 'HIGH',
      description: '__DESCRIPTION__',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: __Rule__Adapter): FindingKey | null {
    return null;
  }
}

export const __rule__Control = new __Rule__Control();
