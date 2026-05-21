import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { S3008Adapter } from './s3-008.adapter.js';

const DISABLED_STATUS = 'Disabled';
const UNRESOLVED_INTRINSIC_KEYS = ['Fn::If', 'Fn::ImportValue'];

export class S3008CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::S3::Bucket'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): S3008CfnAdapter {
    return new S3008CfnAdapter(context);
  }
}

class S3008CfnAdapter implements S3008Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly isBucket: boolean;
  readonly hasLifecycleConfiguration: boolean;

  constructor(ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
    this.isBucket = ctx.resource.Type === 'AWS::S3::Bucket';
    this.hasLifecycleConfiguration = this.detectActiveLifecycleConfiguration(ctx);
  }

  private detectActiveLifecycleConfiguration(ctx: CfnContext): boolean {
    const properties = ctx.resource.Properties as Record<string, unknown> | undefined;
    if (!properties) return false;

    const lifecycle = properties['LifecycleConfiguration'];
    if (lifecycle === undefined || lifecycle === null) return false;

    if (this.isUnresolvedIntrinsic(lifecycle)) return true;

    const rules = (lifecycle as Record<string, unknown>)['Rules'];
    if (!Array.isArray(rules) || rules.length === 0) return false;

    return rules.some(rule => this.isRuleEnabledOrUnresolved(rule));
  }

  private isRuleEnabledOrUnresolved(rule: unknown): boolean {
    if (this.isUnresolvedIntrinsic(rule)) return true;
    if (!rule || typeof rule !== 'object') return false;
    const status = (rule as Record<string, unknown>)['Status'];
    return status !== DISABLED_STATUS;
  }

  private isUnresolvedIntrinsic(value: unknown): boolean {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    return UNRESOLVED_INTRINSIC_KEYS.some(key => key in (value as Record<string, unknown>));
  }
}
