import { AdapterFactory, CfnContext, IacRemediation } from '../../../controls/types.js';
import { S3BucketAdapter } from './s3-bucket-adapter.js';

export class CfnS3BucketAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::S3::Bucket'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): CfnS3BucketBoundAdapter {
    return new CfnS3BucketBoundAdapter(context);
  }
}

class CfnS3BucketBoundAdapter implements S3BucketAdapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isLogDestinationBucket(): boolean {
    const template = this.ctx.template;
    if (!template.Resources || !this.ctx.logicalId) return false;

    for (const [id, res] of Object.entries(template.Resources)) {
      if (res.Type !== 'AWS::S3::Bucket' || id === this.ctx.logicalId) continue;
      const dest = res.Properties?.LoggingConfiguration?.DestinationBucketName;
      if (!dest) continue;
      if (dest === this.ctx.logicalId) return true;
      if (dest?.Ref === this.ctx.logicalId) return true;
      if (dest?.['Fn::GetAtt']?.[0] === this.ctx.logicalId) return true;
    }
    return false;
  }

  getLoggingDestination(): string | null {
    const dest = this.ctx.resource.Properties?.LoggingConfiguration?.DestinationBucketName;
    if (!dest) return null;
    if (typeof dest === 'string') return dest;
    if (dest.Ref) return dest.Ref;
    if (dest['Fn::GetAtt']) return dest['Fn::GetAtt'][0];
    return 'unresolved';
  }

  isSelfLogging(): boolean {
    const dest = this.ctx.resource.Properties?.LoggingConfiguration?.DestinationBucketName;
    if (!dest) return false;
    const bucketName = this.ctx.resource.Properties?.BucketName;
    if (typeof bucketName === 'string' && typeof dest === 'string' && bucketName === dest) return true;
    if (dest?.Ref === this.ctx.logicalId) return true;
    return false;
  }

  getRemediation(scenario: string): IacRemediation | null {
    const remediations: Record<string, IacRemediation> = {
      'missing-logging': {
        scenario: 'missing-logging',
        guidance: 'Add a LoggingConfiguration with DestinationBucketName referencing a dedicated log bucket. Use a BucketPolicy (not AccessControl) to grant logging.s3.amazonaws.com write access.',
      },
      'self-logging': {
        scenario: 'self-logging',
        guidance: 'Change LoggingConfiguration.DestinationBucketName to reference a separate dedicated logging bucket. Use a BucketPolicy (not AccessControl) to grant logging.s3.amazonaws.com write access.',
      },
    };
    return remediations[scenario] ?? null;
  }
}
