import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-001: S3 buckets must have access logging enabled with a dedicated log
 * destination bucket.
 *
 * Uses the template-aware evaluateResource entry point to inspect all buckets in
 * a template together. Buckets that serve as log destinations for other buckets
 * are automatically excluded from evaluation.
 *
 * Checks:
 * - LoggingConfiguration is present with a DestinationBucketName.
 * - The destination bucket is not the source bucket itself (self-logging).
 *
 * Destination bucket references are resolved through literal strings, Ref, and
 * Fn::GetAtt intrinsics.
 *
 * Known limitations:
 * - Templates that conditionally apply LoggingConfiguration via Fn::If or
 *   Fn::Transform will be flagged even if the deployed result is compliant.
 * - CDK L2 Bucket constructs automatically add AccessControl: LogDeliveryWrite
 *   when serverAccessLogsBucket is used. The fix prompts accept this behavior.
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

    const destinationBucket = resource.Properties?.LoggingConfiguration?.DestinationBucketName;
    if (!destinationBucket) {
      return this.createResult(
        stackName,
        template,
        resource,
        this.description,
        `Enable S3 access logging by configuring the source bucket to send access logs to a separate, dedicated logging bucket.
First, check whether the template already contains a dedicated logging bucket that other buckets reference as their logging destination. If one exists, reuse it. If not, create a new S3 bucket to serve as the log destination.
For the logging bucket: configure OwnershipControls with ObjectOwnership set to BucketOwnerPreferred. Do NOT set the AccessControl property at all — instead, add a separate BucketPolicy resource granting the logging.s3.amazonaws.com service s3:PutObject permission on the log bucket ARN (scoped to the log prefix path), with a Condition restricting aws:SourceAccount to the current account.
On the source bucket, add a LoggingConfiguration with DestinationBucketName referencing the logging bucket and a LogFilePrefix that includes the source bucket's logical name (e.g. "DataBucket/access-logs/").
In CDK, use the objectOwnership property set to BUCKET_OWNER_PREFERRED on the log bucket, and the serverAccessLogsBucket/serverAccessLogsPrefix properties on the source bucket. Add the bucket policy via addToResourcePolicy. Note: CDK automatically adds AccessControl: LogDeliveryWrite to the log bucket when serverAccessLogsBucket is used — this is expected and acceptable.
Do NOT log to the same bucket (self-logging). For raw CloudFormation, do NOT set AccessControl on any bucket — use only BucketPolicy for permissions.`
);
    }

    if (this.isSelfLogging(resource, destinationBucket, logicalId)) {
      return this.createResult(
        stackName,
        template,
        resource,
        this.description,
        `Redirect access logs from the self-logging bucket to a separate, dedicated logging bucket.
First, check whether the template already contains a dedicated logging bucket that other buckets reference as their logging destination. If one exists, reuse it. If not, create a new S3 bucket to serve as the log destination. Configure the logging bucket with OwnershipControls setting ObjectOwnership to BucketOwnerPreferred.
Add an AWS::S3::BucketPolicy on the logging bucket granting the logging.s3.amazonaws.com service s3:PutObject permission on the bucket's ARN scoped to the log prefix path. Include a Condition restricting aws:SourceAccount to the current account (use !Ref AWS::AccountId).
On the original bucket, change the LoggingConfiguration.DestinationBucketName to reference the logging bucket using !Ref. Set LogFilePrefix to something like "access-logs/".
In CDK, use the objectOwnership property set to BUCKET_OWNER_PREFERRED on the log bucket, and the serverAccessLogsBucket/serverAccessLogsPrefix properties on the source bucket. Add the bucket policy via addToResourcePolicy. Note: CDK automatically adds AccessControl: LogDeliveryWrite to the log bucket when serverAccessLogsBucket is used — this is expected and acceptable.
Do NOT log to the same bucket (self-logging). For raw CloudFormation, do NOT set AccessControl on any bucket — use only BucketPolicy for permissions.`
      );
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
