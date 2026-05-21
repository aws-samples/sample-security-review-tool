import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { S3008Adapter } from './s3-008.adapter.js';

const BUCKET_TYPE = 'aws_s3_bucket';
const LIFECYCLE_TYPE = 'aws_s3_bucket_lifecycle_configuration';
const DISABLED_STATUS = 'Disabled';

export class S3008TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [BUCKET_TYPE, LIFECYCLE_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): S3008TfAdapter {
    return new S3008TfAdapter(context);
  }
}

class S3008TfAdapter implements S3008Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly isBucket: boolean;
  readonly hasLifecycleConfiguration: boolean;

  constructor(ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
    this.isBucket = ctx.resource.type === BUCKET_TYPE;
    this.hasLifecycleConfiguration = this.isBucket
      ? this.hasActiveLifecycleConfigurationFor(ctx.resource, ctx.allResources)
      : true;
  }

  private hasActiveLifecycleConfigurationFor(bucket: TerraformResource, allResources: TerraformResource[]): boolean {
    const associatedLifecycles = allResources
      .filter(r => r.type === LIFECYCLE_TYPE)
      .filter(lifecycle => this.referencesBucket(lifecycle, bucket));
    return associatedLifecycles.some(lifecycle => this.hasAnyEnabledRule(lifecycle));
  }

  private referencesBucket(lifecycle: TerraformResource, bucket: TerraformResource): boolean {
    const lifecycleBucketRef = (lifecycle.values as Record<string, unknown> | undefined)?.['bucket'];
    const bucketName = (bucket.values as Record<string, unknown> | undefined)?.['bucket'];
    const bucketId = (bucket.values as Record<string, unknown> | undefined)?.['id'];

    if (typeof lifecycleBucketRef !== 'string') return false;
    return lifecycleBucketRef === bucketName || lifecycleBucketRef === bucketId || lifecycleBucketRef === bucket.address;
  }

  private hasAnyEnabledRule(lifecycle: TerraformResource): boolean {
    const rules = (lifecycle.values as Record<string, unknown> | undefined)?.['rule'];
    if (!Array.isArray(rules) || rules.length === 0) return false;
    return rules.some(rule => this.isRuleEnabled(rule));
  }

  private isRuleEnabled(rule: unknown): boolean {
    if (!rule || typeof rule !== 'object') return false;
    const status = (rule as Record<string, unknown>)['status'];
    return status !== DISABLED_STATUS;
  }
}
