import { AdapterFactory, CfnContext, IacRemediation } from '../../../controls/types.js';
import { S3Adapter } from './s3-adapter.js';

export class CfnS3AdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): CfnS3Adapter {
    return new CfnS3Adapter(context);
  }
}

class CfnS3Adapter implements S3Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
