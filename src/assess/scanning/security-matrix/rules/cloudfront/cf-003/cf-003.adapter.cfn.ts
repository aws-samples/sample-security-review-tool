import { AdapterFactory, CfnContext, Resource, Template } from '../../../controls/types.js';
import { Cf003Adapter } from './cf-003.adapter.js';

const DISTRIBUTION_TYPE = 'AWS::CloudFront::Distribution';
const DELIVERY_SOURCE_TYPE = 'AWS::Logs::DeliverySource';
const DELIVERY_DESTINATION_TYPE = 'AWS::Logs::DeliveryDestination';
const MONITORING_SUBSCRIPTION_TYPE = 'AWS::CloudFront::MonitoringSubscription';

export class Cf003CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = [DISTRIBUTION_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf003CfnAdapter {
    return new Cf003CfnAdapter(context);
  }
}

class Cf003CfnAdapter implements Cf003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly hasAccessLogging: boolean;

  constructor(ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
    this.hasAccessLogging =
      this.hasInlineLogging(ctx.resource) ||
      this.hasCompleteExternalDeliveryChain(ctx.template, ctx.logicalId);
  }

  private hasInlineLogging(resource: Resource): boolean {
    const logging = resource.Properties?.DistributionConfig?.Logging;
    if (logging === undefined || logging === null) return false;
    return this.hasValidLoggingBucket(logging);
  }

  private hasValidLoggingBucket(logging: unknown): boolean {
    if (typeof logging !== 'object' || logging === null) return false;
    const bucket = (logging as { Bucket?: unknown }).Bucket;
    if (bucket === undefined || bucket === null) return false;
    if (typeof bucket === 'string') return bucket.length > 0;
    return true;
  }

  private hasCompleteExternalDeliveryChain(template: Template, distributionLogicalId: string): boolean {
    const resources = Object.values(template.Resources ?? {});
    const hasSourceReferencingDistribution = resources.some(resource =>
      this.isDeliverySourceFor(resource, distributionLogicalId),
    );
    if (!hasSourceReferencingDistribution) {
      return this.hasMonitoringSubscriptionFor(resources, distributionLogicalId);
    }
    return resources.some(resource => resource.Type === DELIVERY_DESTINATION_TYPE);
  }

  private isDeliverySourceFor(resource: Resource, distributionLogicalId: string): boolean {
    if (resource.Type !== DELIVERY_SOURCE_TYPE) return false;
    return this.referencesLogicalId(resource, distributionLogicalId);
  }

  private hasMonitoringSubscriptionFor(resources: Resource[], distributionLogicalId: string): boolean {
    return resources.some(
      resource =>
        resource.Type === MONITORING_SUBSCRIPTION_TYPE &&
        this.referencesLogicalId(resource, distributionLogicalId),
    );
  }

  private referencesLogicalId(resource: Resource, logicalId: string): boolean {
    const serialized = JSON.stringify(resource.Properties ?? {});
    return serialized.includes(`"${logicalId}"`);
  }
}
