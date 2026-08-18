import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { As004Adapter } from './as-004.adapter.js';
import { namesApplicationHealthCheck } from './as-004.health-check-type.js';

const ATTACHMENT_PROPERTIES = ['LoadBalancerNames', 'TargetGroupARNs', 'TrafficSources'] as const;

export class As004CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::AutoScaling::AutoScalingGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): As004CfnAdapter {
    return new As004CfnAdapter(context);
  }
}

class As004CfnAdapter implements As004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isAttachedToLoadBalancer(): boolean {
    return ATTACHMENT_PROPERTIES.some(name => this.hasEntries(this.properties[name]));
  }

  usesInstanceStatusHealthChecksOnly(): boolean {
    const healthCheckType = this.properties['HealthCheckType'];
    if (healthCheckType === undefined) return true;
    if (typeof healthCheckType !== 'string') return false;
    return !namesApplicationHealthCheck(healthCheckType);
  }

  private get properties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
  }

  private hasEntries(value: unknown): boolean {
    return Array.isArray(value) && value.length > 0;
  }
}
