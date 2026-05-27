import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Cf004Adapter } from './cf-004.adapter.js';

const HTTP_ALLOWING_POLICIES = new Set(['allow-all']);

export class Cf004CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf004CfnAdapter {
    return new Cf004CfnAdapter(context);
  }
}

class Cf004CfnAdapter implements Cf004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasDefaultCacheBehaviorViewerProtocolPolicy(): boolean {
    const defaultCacheBehavior = this.getDefaultCacheBehavior();
    if (!defaultCacheBehavior) return false;
    return 'ViewerProtocolPolicy' in defaultCacheBehavior;
  }

  defaultCacheBehaviorAllowsHttp(): boolean {
    const policy = this.getDefaultViewerProtocolPolicy();
    return this.policyAllowsHttp(policy);
  }

  hasAdditionalCacheBehaviorAllowingHttp(): boolean {
    const behaviors = this.getAdditionalCacheBehaviors();
    return behaviors.some(behavior => this.policyAllowsHttp(behavior?.['ViewerProtocolPolicy']));
  }

  private policyAllowsHttp(policy: unknown): boolean {
    if (typeof policy !== 'string') return false;
    return HTTP_ALLOWING_POLICIES.has(policy);
  }

  private getDefaultViewerProtocolPolicy(): unknown {
    return this.getDefaultCacheBehavior()?.['ViewerProtocolPolicy'];
  }

  private getDefaultCacheBehavior(): Record<string, unknown> | undefined {
    return this.getDistributionConfig()?.['DefaultCacheBehavior'] as Record<string, unknown> | undefined;
  }

  private getAdditionalCacheBehaviors(): Array<Record<string, unknown> | undefined> {
    const cacheBehaviors = this.getDistributionConfig()?.['CacheBehaviors'];
    if (!Array.isArray(cacheBehaviors)) return [];
    return cacheBehaviors as Array<Record<string, unknown> | undefined>;
  }

  private getDistributionConfig(): Record<string, unknown> | undefined {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    return properties?.['DistributionConfig'] as Record<string, unknown> | undefined;
  }
}
