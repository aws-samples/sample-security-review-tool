import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfS3001Rule extends BaseTerraformRule {
  constructor() {
    super('S3-001', 'HIGH', 'S3 bucket lacks proper access logging configuration', ['aws_s3_bucket', 'aws_s3_bucket_logging']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_s3_bucket') {
      return this.evaluateBucket(resource, projectName, allResources);
    }
    return null;
  }

  private evaluateBucket(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (this.isLogDestinationBucket(resource, allResources)) return null;

    if (this.hasLoggingResource(resource, allResources)) return null;

    const logging = resource.values?.logging;
    if (logging) {
      const targetBucket = Array.isArray(logging) ? logging[0]?.target_bucket : logging.target_bucket;
      if (targetBucket) {
        if (this.isSelfLogging(resource, targetBucket)) {
          return this.createScanResult(resource, projectName, this.description,
            'Redirect access logs to a separate dedicated logging bucket instead of logging to the same bucket.');
        }
        return null;
      }
    }

    return this.createScanResult(resource, projectName, this.description,
      'Enable access logging by adding an aws_s3_bucket_logging resource targeting a dedicated log bucket, or configure the logging block with a target_bucket pointing to a separate bucket.');
  }

  private hasLoggingResource(bucket: TerraformResource, allResources: TerraformResource[]): boolean {
    return allResources.some(r =>
      r.type === 'aws_s3_bucket_logging' &&
      (r.values?.bucket === bucket.values?.bucket || r.values?.bucket === bucket.values?.id)
    );
  }

  private isLogDestinationBucket(bucket: TerraformResource, allResources: TerraformResource[]): boolean {
    const bucketId = bucket.values?.bucket || bucket.values?.id;
    if (!bucketId) return false;

    return allResources.some(r => {
      if (r.type === 'aws_s3_bucket_logging') {
        return r.values?.target_bucket === bucketId;
      }
      if (r.type === 'aws_s3_bucket' && r !== bucket) {
        const logging = r.values?.logging;
        const targetBucket = Array.isArray(logging) ? logging[0]?.target_bucket : logging?.target_bucket;
        return targetBucket === bucketId;
      }
      return false;
    });
  }

  private isSelfLogging(bucket: TerraformResource, targetBucket: string): boolean {
    const bucketName = bucket.values?.bucket || bucket.values?.id;
    return bucketName === targetBucket;
  }
}

export default new TfS3001Rule();
