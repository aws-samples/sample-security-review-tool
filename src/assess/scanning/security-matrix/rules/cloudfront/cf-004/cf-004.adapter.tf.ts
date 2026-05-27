import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Cf004Adapter } from './cf-004.adapter.js';

const HTTP_ALLOWING_POLICIES = new Set(['allow-all']);

export class Cf004TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_cloudfront_distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf004TfAdapter {
    return new Cf004TfAdapter(context);
  }
}

class Cf004TfAdapter implements Cf004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasDefaultCacheBehaviorViewerProtocolPolicy(): boolean {
    const defaultCacheBehavior = this.getDefaultCacheBehavior();
    if (!defaultCacheBehavior) return false;
    return 'viewer_protocol_policy' in defaultCacheBehavior;
  }

  defaultCacheBehaviorAllowsHttp(): boolean {
    const policy = this.getDefaultViewerProtocolPolicy();
    return this.policyAllowsHttp(policy);
  }

  hasAdditionalCacheBehaviorAllowingHttp(): boolean {
    const behaviors = this.getOrderedCacheBehaviors();
    return behaviors.some(behavior => this.policyAllowsHttp(behavior?.['viewer_protocol_policy']));
  }

  private policyAllowsHttp(policy: unknown): boolean {
    if (typeof policy !== 'string') return false;
    return HTTP_ALLOWING_POLICIES.has(policy);
  }

  private getDefaultViewerProtocolPolicy(): unknown {
    return this.getDefaultCacheBehavior()?.['viewer_protocol_policy'];
  }

  private getDefaultCacheBehavior(): Record<string, unknown> | undefined {
    const defaultCacheBehaviors = this.normalizeToArray(this.getValues()?.['default_cache_behavior']);
    if (defaultCacheBehaviors.length === 0) return undefined;
    return defaultCacheBehaviors[0] as Record<string, unknown> | undefined;
  }

  private getOrderedCacheBehaviors(): Array<Record<string, unknown> | undefined> {
    const behaviors = this.normalizeToArray(this.getValues()?.['ordered_cache_behavior']);
    return behaviors as Array<Record<string, unknown> | undefined>;
  }

  private getValues(): Record<string, unknown> | undefined {
    return this.ctx.resource.values as Record<string, unknown> | undefined;
  }

  private normalizeToArray(value: unknown): unknown[] {
    if (Array.isArray(value)) return value;
    if (value === undefined || value === null) return [];
    return [value];
  }
}
