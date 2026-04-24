import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-001 Rule: Ensure that access logging is enabled on all in-scope S3 buckets
 * with a dedicated log destination bucket.
 */
export class S3001Rule extends BaseRule {
  constructor() {
    super(
      'S3-001',
      'HIGH',
      'S3 bucket lacks proper access logging configuration',
      ['AWS::S3::Bucket']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (resource.Type === 'AWS::S3::Bucket') {
      return this.evaluateBucket(stackName, template, resource);
    }
    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    return null;
  }

  private evaluateBucket(stackName: string, template: Template, resource: Resource): ScanResult | null {
    const logicalId = this.getLogicalId(template, resource);
    if (this.isLogDestinationBucket(template, logicalId)) {
      return null;
    }

    const loggingConfiguration = resource.Properties?.LoggingConfiguration;
    if (!loggingConfiguration) {
      return this.createResult(stackName, template, resource, this.description, 'Enable S3 access logging with a dedicated log bucket.');
    }

    const destinationBucket = loggingConfiguration.DestinationBucketName;
    if (!destinationBucket) {
      return this.createResult(stackName, template, resource, this.description, 'Set DestinationBucketName in LoggingConfiguration to specify where access logs should be stored.');
    }

    if (this.isSelfLogging(resource, destinationBucket, logicalId)) {
      return this.createResult(stackName, template, resource, this.description, 'Use a dedicated logging bucket different from the source bucket to prevent log loss.');
    }

    return null;
  }

  private getLogicalId(template: Template, resource: Resource): string {
    if (!template.Resources) return '';
    const entry = Object.entries(template.Resources).find(([_, res]) => res === resource);
    return entry ? entry[0] : '';
  }

  private isLogDestinationBucket(template: Template, logicalId: string): boolean {
    if (!template.Resources || !logicalId) return false;

    for (const [id, res] of Object.entries(template.Resources)) {
      if (res.Type !== 'AWS::S3::Bucket' || id === logicalId) continue;

      const destBucket = res.Properties?.LoggingConfiguration?.DestinationBucketName;
      if (!destBucket) continue;

      if (destBucket === logicalId) return true;
      if (destBucket?.Ref === logicalId) return true;
      if (destBucket?.['Fn::GetAtt']?.[0] === logicalId) return true;
    }
    return false;
  }

  private isSelfLogging(resource: Resource, destinationBucket: any, logicalId: string): boolean {
    const bucketName = resource.Properties?.BucketName;
    if (typeof bucketName === 'string' && typeof destinationBucket === 'string' && bucketName === destinationBucket) {
      return true;
    }
    if (destinationBucket?.Ref === logicalId) return true;
    return false;
  }
}

export default new S3001Rule();
