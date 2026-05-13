import { AdapterFactory, TfContext, IacRemediation } from '../../../controls/types.js';
import { S3BucketAdapter } from './s3-bucket-adapter.js';

export class TfS3BucketAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_s3_bucket'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): TfS3BucketBoundAdapter {
    return new TfS3BucketBoundAdapter(context);
  }
}

class TfS3BucketBoundAdapter implements S3BucketAdapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isLogDestinationBucket(): boolean {
    const bucketId = this.ctx.resource.values?.bucket || this.ctx.resource.values?.id;
    if (!bucketId) return false;

    return this.ctx.allResources.some(r => {
      if (r.type === 'aws_s3_bucket_logging') return r.values?.target_bucket === bucketId;
      if (r.type === 'aws_s3_bucket' && r !== this.ctx.resource) {
        const logging = r.values?.logging;
        const target = Array.isArray(logging) ? logging[0]?.target_bucket : logging?.target_bucket;
        return target === bucketId;
      }
      return false;
    });
  }

  getLoggingDestination(): string | null {
    const bucketId = this.ctx.resource.values?.bucket || this.ctx.resource.values?.id;
    const loggingRes = this.ctx.allResources.find(r => r.type === 'aws_s3_bucket_logging' && (r.values?.bucket === bucketId || r.values?.bucket === this.ctx.resource.values?.id));
    if (loggingRes) return loggingRes.values?.target_bucket ?? null;

    const logging = this.ctx.resource.values?.logging;
    const target = Array.isArray(logging) ? logging[0]?.target_bucket : logging?.target_bucket;
    return target ?? null;
  }

  isSelfLogging(): boolean {
    const dest = this.getLoggingDestination();
    if (!dest) return false;
    const bucketName = this.ctx.resource.values?.bucket || this.ctx.resource.values?.id;
    return bucketName === dest;
  }

  getRemediation(scenario: string): IacRemediation | null {
    const remediations: Record<string, IacRemediation> = {
      'missing-logging': {
        scenario: 'missing-logging',
        guidance: 'Add an aws_s3_bucket_logging resource targeting a dedicated log bucket.',
      },
      'self-logging': {
        scenario: 'self-logging',
        guidance: 'Change the target_bucket in the aws_s3_bucket_logging resource to reference a separate dedicated logging bucket.',
      },
    };
    return remediations[scenario] ?? null;
  }
}
