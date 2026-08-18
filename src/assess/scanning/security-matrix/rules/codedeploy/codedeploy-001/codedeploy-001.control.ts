import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Codedeploy001Adapter } from './codedeploy-001.adapter.js';

const FINDINGS = {
  NO_ALARM_MONITORING: {
    issue: 'The CodeDeploy deployment group has no CloudWatch alarm monitoring in effect, because it either names no alarm or leaves the alarm configuration switched off, so a triggered alarm cannot stop or roll back a deployment',
    remediation: 'Associate at least one CloudWatch alarm with the deployment group and switch the alarm configuration on, so that deployment health is monitored and a triggered alarm can stop or roll back the deployment.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Codedeploy001Control extends SecurityControl<Codedeploy001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CODEDEPLOY-001',
      priority: 'HIGH',
      description: 'CodeDeploy deployment groups must have at least one CloudWatch alarm configured to monitor deployments',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Codedeploy001Adapter): FindingKey | null {
    const hasAlarms = adapter.hasConfiguredAlarms();
    if (hasAlarms === undefined) return null;
    return hasAlarms ? null : 'NO_ALARM_MONITORING';
  }
}

export const codedeploy001Control = new Codedeploy001Control();
