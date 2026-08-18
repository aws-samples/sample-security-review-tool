import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { As004Adapter } from './as-004.adapter.js';

const FINDINGS = {
  INSTANCE_STATUS_HEALTH_CHECKS_ONLY: {
    issue:
      'The Auto Scaling group is attached to a load balancer or target group but its health checks only consider EC2 instance status, so instances that are running yet reported unhealthy by the load balancer are never replaced',
    remediation:
      'Configure the Auto Scaling group to use Elastic Load Balancing health checks in addition to instance status checks, so the group replaces instances the load balancer reports as unhealthy.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class As004Control extends SecurityControl<As004Adapter, FindingKey> {
  constructor() {
    super({
      id: 'AS-004',
      priority: 'HIGH',
      description: 'Auto Scaling Groups attached to a load balancer or target group must use Elastic Load Balancing health checks rather than EC2 instance status checks alone',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: As004Adapter): FindingKey | null {
    if (!adapter.isAttachedToLoadBalancer()) return null;
    if (!adapter.usesInstanceStatusHealthChecksOnly()) return null;
    return 'INSTANCE_STATUS_HEALTH_CHECKS_ONLY';
  }
}

export const as004Control = new As004Control();
