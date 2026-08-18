import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { As004Adapter } from './as-004.adapter.js';
import { namesApplicationHealthCheck } from './as-004.health-check-type.js';

const ATTACHMENT_ARGUMENTS = ['load_balancers', 'target_group_arns', 'traffic_source'] as const;

export class As004TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_autoscaling_group', 'aws_autoscaling_attachment', 'aws_autoscaling_traffic_source_attachment'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): As004TfAdapter {
    return new As004TfAdapter(context);
  }
}

class As004TfAdapter implements As004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isAttachedToLoadBalancer(): boolean {
    if (!this.isGroup) return false;
    return ATTACHMENT_ARGUMENTS.some(name => this.hasEntries(this.values[name]))
      || this.hasExternalAttachment();
  }

  usesInstanceStatusHealthChecksOnly(): boolean {
    if (!this.isGroup) return false;
    const healthCheckType = this.values['health_check_type'];
    if (healthCheckType === undefined) return true;
    if (typeof healthCheckType !== 'string' || isUnresolved(healthCheckType)) return false;
    return !namesApplicationHealthCheck(healthCheckType);
  }

  private get isGroup(): boolean {
    return this.ctx.resource.type === 'aws_autoscaling_group';
  }

  private get values(): Record<string, unknown> {
    return (this.ctx.resource.values ?? {}) as Record<string, unknown>;
  }

  private hasEntries(value: unknown): boolean {
    if (Array.isArray(value)) return value.length > 0;
    return typeof value === 'string' && !isUnresolved(value) && value.length > 0;
  }

  private hasExternalAttachment(): boolean {
    return this.ctx.allResources.some(resource => this.attachesToGroup(resource));
  }

  private attachesToGroup(resource: TerraformResource): boolean {
    if (resource.type !== 'aws_autoscaling_attachment'
      && resource.type !== 'aws_autoscaling_traffic_source_attachment') return false;
    const target = (resource.values as Record<string, unknown>)?.['autoscaling_group_name'];
    if (typeof target !== 'string') return false;
    if (target === this.ctx.resource.address) return true;
    const literalName = this.values['name'];
    return typeof literalName === 'string' && target === literalName;
  }
}
