import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { S3001Adapter } from './s3-001.adapter.js';

const S3_BUCKET_TYPE = 'aws_s3_bucket';
const S3_BUCKET_LOGGING_TYPE = 'aws_s3_bucket_logging';

export class S3001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [S3_BUCKET_TYPE, S3_BUCKET_LOGGING_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): S3001TfAdapter {
    return new S3001TfAdapter(context);
  }
}

class S3001TfAdapter implements S3001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasLoggingConfigured(): boolean {
    if (this.ctx.resource.type !== S3_BUCKET_TYPE) return true;
    if (this.hasInlineLogging()) return true;
    if (this.hasUnknownInlineLogging()) return true;
    return this.loggingResources().some(logging => this.loggingConfiguresBucket(logging, this.ctx.resource));
  }

  isLogDestination(): boolean {
    if (this.ctx.resource.type !== S3_BUCKET_TYPE) return false;
    return this.loggingResources().some(logging => this.loggingUsesAsDestination(logging, this.ctx.resource));
  }

  private hasInlineLogging(): boolean {
    const logging = this.getValues(this.ctx.resource)['logging'];
    if (Array.isArray(logging)) return logging.length > 0;
    if (logging === undefined || logging === null) return false;
    return true;
  }

  private hasUnknownInlineLogging(): boolean {
    const values = this.getValues(this.ctx.resource);
    if (!('logging' in values)) return false;
    return values['logging'] === null;
  }

  private loggingResources(): TerraformResource[] {
    return this.ctx.allResources.filter(r => r.type === S3_BUCKET_LOGGING_TYPE);
  }

  /**
   * A separate aws_s3_bucket_logging resource counts as configuring the bucket
   * only if BOTH:
   *   - it points its `bucket` field at this bucket (or the bucket field is
   *     unknown/null, in which case we treat it as possibly targeting), AND
   *   - it has a `target_bucket` that actually delivers the logs somewhere.
   * An "empty" logging block (bucket set, target_bucket missing) does not
   * actually enable log delivery and must NOT be treated as configured.
   */
  private loggingConfiguresBucket(logging: TerraformResource, bucket: TerraformResource): boolean {
    if (!this.loggingMayTargetBucket(logging, bucket)) return false;
    return this.hasResolvedTargetBucket(logging);
  }

  private loggingMayTargetBucket(logging: TerraformResource, bucket: TerraformResource): boolean {
    const value = this.getValues(logging)['bucket'];
    // Unknown association: the plan reader could not collapse the `bucket`
    // expression to a single address. We cannot rule out that it targets this
    // bucket, so treat it as configured (pass).
    if (value === null) return true;
    return this.fieldReferencesBucket(logging, 'bucket', bucket);
  }

  private hasResolvedTargetBucket(logging: TerraformResource): boolean {
    const target = this.getValues(logging)['target_bucket'];
    // Unknown target — treat as configured (pass).
    if (target === null) return true;
    return typeof target === 'string' && target.length > 0;
  }

  private loggingUsesAsDestination(logging: TerraformResource, bucket: TerraformResource): boolean {
    return this.fieldReferencesBucket(logging, 'target_bucket', bucket);
  }

  private fieldReferencesBucket(resource: TerraformResource, field: string, bucket: TerraformResource): boolean {
    const value = this.getValues(resource)[field];
    if (typeof value !== 'string') return false;
    if (value === bucket.address) return true;
    const literalName = this.getValues(bucket)['bucket'];
    return typeof literalName === 'string' && value === literalName;
  }

  private getValues(resource: TerraformResource): Record<string, unknown> {
    const values = (resource as { values?: unknown }).values;
    return values && typeof values === 'object' ? (values as Record<string, unknown>) : {};
  }
}
