import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { As005Adapter } from './as-005.adapter.js';
import { externalCheck } from '../../../../remediation/external-check.js';

const LAUNCH_TEMPLATE_REMEDIATION =
  'Define the instance settings in a launch template and point the Auto Scaling group at that launch template (directly or through a mixed instances policy) instead of a launch configuration.';

const FINDINGS = {
  LAUNCH_CONFIGURATION_ONLY: {
    issue:
      'The Auto Scaling group gets its instance configuration only from a launch configuration, a deprecated mechanism, and has no launch template or mixed instances policy.',
    remediation: LAUNCH_TEMPLATE_REMEDIATION,
  },
  EXISTING_INSTANCE_SOURCE: {
    issue:
      'The Auto Scaling group takes its instance configuration from the identifier of an existing EC2 instance, which makes the group run on a launch configuration generated from that instance instead of a launch template or mixed instances policy.',
    remediation: LAUNCH_TEMPLATE_REMEDIATION,
  },
  MIXED_INSTANCES_POLICY_WITHOUT_LAUNCH_TEMPLATE: {
    issue:
      'The Auto Scaling group defines a mixed instances policy that names no launch template, so no launch template is in effect for the group.',
    remediation: LAUNCH_TEMPLATE_REMEDIATION,
  },
  UNUSABLE_LAUNCH_TEMPLATE_REFERENCE: {
    issue:
      'The Auto Scaling group declares a launch template reference that identifies no launch template, because it supplies neither a launch template identifier nor a launch template name, so no launch template is in effect for the group.',
    remediation: LAUNCH_TEMPLATE_REMEDIATION,
  },
  NO_LAUNCH_SOURCE: {
    issue:
      'The Auto Scaling group declares no instance configuration source at all: neither a launch configuration, nor a launch template, nor a mixed instances policy, so it does not run on a launch template.',
    remediation: LAUNCH_TEMPLATE_REMEDIATION,
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class As005Control extends SecurityControl<As005Adapter, FindingKey> {
  constructor() {
    super({
      id: 'AS-005',
      priority: 'HIGH',
      description: 'Auto Scaling groups must be configured to use a launch template rather than a launch configuration',
      findings: FINDINGS,
      relatedRules: [externalCheck('CKV_AWS_79')],
    });
  }

  protected evaluate(adapter: As005Adapter): FindingKey | null {
    if (adapter.usesLaunchTemplate() || adapter.mixedInstancesPolicyUsesLaunchTemplate()) return null;
    if (adapter.declaresLaunchTemplateReference()) return 'UNUSABLE_LAUNCH_TEMPLATE_REFERENCE';
    if (adapter.hasMixedInstancesPolicy()) return 'MIXED_INSTANCES_POLICY_WITHOUT_LAUNCH_TEMPLATE';
    if (adapter.usesLaunchConfiguration()) return 'LAUNCH_CONFIGURATION_ONLY';
    return adapter.usesExistingInstance() ? 'EXISTING_INSTANCE_SOURCE' : 'NO_LAUNCH_SOURCE';
  }
}

export const as005Control = new As005Control();
