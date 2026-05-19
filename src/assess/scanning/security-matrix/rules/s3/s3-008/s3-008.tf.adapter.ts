import { AdapterFactory, TfContext, IacRemediation } from '../../../controls/types.js';
import { S3Adapter } from './s3-adapter.js';

export class TfS3AdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_s3_bucket', 'aws_s3_bucket_lifecycle_configuration'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): TfS3Adapter {
    return new TfS3Adapter(context);
  }
}

class TfS3Adapter implements S3Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
