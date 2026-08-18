import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { As005Adapter } from './as-005.adapter.js';

const LAUNCH_TEMPLATE_IDENTIFIERS = ['LaunchTemplateId', 'LaunchTemplateName'] as const;

export class As005CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::AutoScaling::AutoScalingGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): As005CfnAdapter {
    return new As005CfnAdapter(context);
  }
}

class As005CfnAdapter implements As005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  usesLaunchConfiguration(): boolean {
    return this.isPresent(this.property('LaunchConfigurationName'));
  }

  declaresLaunchTemplateReference(): boolean {
    return this.isPresent(this.property('LaunchTemplate'));
  }

  usesLaunchTemplate(): boolean {
    return this.identifiesLaunchTemplate(this.property('LaunchTemplate'));
  }

  hasMixedInstancesPolicy(): boolean {
    return this.isPresent(this.property('MixedInstancesPolicy'));
  }

  mixedInstancesPolicyUsesLaunchTemplate(): boolean {
    const policy = this.property('MixedInstancesPolicy');
    if (!this.isPresent(policy)) return false;
    if (!this.isInspectableRecord(policy)) return true;

    const launchTemplate = policy['LaunchTemplate'];
    if (!this.isPresent(launchTemplate)) return false;
    if (!this.isInspectableRecord(launchTemplate)) return true;

    return this.identifiesLaunchTemplate(launchTemplate['LaunchTemplateSpecification']);
  }

  usesExistingInstance(): boolean {
    return this.isPresent(this.property('InstanceId'));
  }

  /** A reference identifies a launch template when it names one by id or name, or cannot be read. */
  private identifiesLaunchTemplate(reference: unknown): boolean {
    if (!this.isPresent(reference)) return false;
    if (!this.isInspectableRecord(reference)) return true;
    return LAUNCH_TEMPLATE_IDENTIFIERS.some(key => this.isPresent(reference[key]));
  }

  private property(name: string): unknown {
    const properties = (this.ctx.resource as { Properties?: Record<string, unknown> }).Properties;
    return properties?.[name];
  }

  /** A plain object whose keys are readable properties rather than an unresolved intrinsic. */
  private isInspectableRecord(value: unknown): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    return !Object.keys(value).some(key => key.startsWith('Fn::') || key === 'Ref');
  }

  private isPresent(value: unknown): boolean {
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.trim().length > 0;
    return true;
  }
}
