import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { As001Adapter, CooldownState } from './as-001.adapter.js';
import { classifyCooldown } from './as-001.cooldown.js';

export class As001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_autoscaling_group'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): As001TfAdapter {
    return new As001TfAdapter(context);
  }
}

class As001TfAdapter implements As001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  get cooldownState(): CooldownState {
    const values = this.ctx.resource.values as Record<string, unknown> | undefined;
    const cooldown = values?.['default_cooldown'];
    if (isUnresolved(cooldown)) return 'unknown';
    return classifyCooldown(cooldown);
  }
}
