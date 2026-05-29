import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Cf003Adapter } from './cf-003.adapter.js';

const DISTRIBUTION_TYPE = 'aws_cloudfront_distribution';
const LOG_DELIVERY_SOURCE_TYPE = 'aws_cloudwatch_log_delivery_source';
const LOG_DELIVERY_DESTINATION_TYPE = 'aws_cloudwatch_log_delivery_destination';

export class Cf003TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [DISTRIBUTION_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf003TfAdapter {
    return new Cf003TfAdapter(context);
  }
}

class Cf003TfAdapter implements Cf003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly hasAccessLogging: boolean;

  constructor(ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
    this.hasAccessLogging =
      this.hasInlineLogging(ctx.resource) ||
      this.hasCompleteExternalDeliveryChain(ctx.allResources, ctx.resource.address);
  }

  private hasInlineLogging(resource: TerraformResource): boolean {
    const values = (resource as unknown as { values?: Record<string, unknown> }).values ?? {};
    const loggingConfig = values.logging_config;
    if (loggingConfig === undefined || loggingConfig === null) return false;
    const entries = Array.isArray(loggingConfig) ? loggingConfig : [loggingConfig];
    if (entries.length === 0) return false;
    return entries.some(entry => this.hasValidLoggingBucket(entry));
  }

  private hasValidLoggingBucket(entry: unknown): boolean {
    if (typeof entry !== 'object' || entry === null) return false;
    const bucket = (entry as { bucket?: unknown }).bucket;
    if (bucket === undefined || bucket === null) return false;
    if (typeof bucket === 'string') return bucket.length > 0;
    return true;
  }

  private hasCompleteExternalDeliveryChain(
    allResources: TerraformResource[],
    distributionAddress: string,
  ): boolean {
    const hasSourceReferencingDistribution = allResources.some(resource =>
      this.isDeliverySourceFor(resource, distributionAddress),
    );
    if (!hasSourceReferencingDistribution) return false;
    return allResources.some(resource => resource.type === LOG_DELIVERY_DESTINATION_TYPE);
  }

  private isDeliverySourceFor(resource: TerraformResource, distributionAddress: string): boolean {
    if (resource.type !== LOG_DELIVERY_SOURCE_TYPE) return false;
    const serialized = JSON.stringify(resource);
    return serialized.includes(distributionAddress);
  }
}
