import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { As001Adapter, CooldownState } from './as-001.adapter.js';
import { classifyCooldown } from './as-001.cooldown.js';

export class As001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::AutoScaling::AutoScalingGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): As001CfnAdapter {
    return new As001CfnAdapter(context);
  }
}

class As001CfnAdapter implements As001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  get cooldownState(): CooldownState {
    const cooldown = (this.ctx.resource.Properties as Record<string, unknown> | undefined)?.['Cooldown'];
    return classifyCooldown(cooldown);
  }
}
