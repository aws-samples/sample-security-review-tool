import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfS3001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'S3-001',
      'HIGH',
      'S3 bucket violates access logging or least privilege requirements',
      ['aws_s3_bucket', 'aws_s3_bucket_policy']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_s3_bucket') {
      return this.evaluateBucket(resource, projectName, allResources);
    }

    if (resource.type === 'aws_s3_bucket_policy') {
      return this.evaluateBucketPolicy(resource, projectName);
    }

    return null;
  }

  private evaluateBucket(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (this.isLogDestinationBucket(resource, allResources)) {
      return null;
    }

    const hasLogging = this.hasLoggingConfiguration(resource, allResources);
    if (!hasLogging) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Configure an aws_s3_bucket_logging resource to enable S3 access logging with a dedicated log bucket.'
      );
    }

    return null;
  }

  private evaluateBucketPolicy(resource: TerraformResource, projectName: string): ScanResult | null {
    const policy = resource.values?.policy;
    if (!policy || typeof policy !== 'string') return null;

    try {
      const policyDoc = JSON.parse(policy);
      const statements = policyDoc.Statement || [];

      for (const statement of statements) {
        if (statement.Effect !== 'Allow') continue;

        if (this.hasOverlyBroadActions(statement) && this.hasWildcardPrincipal(statement)) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Replace wildcard actions (*) with specific S3 actions needed (e.g., s3:GetObject, s3:PutObject).'
          );
        }

        if (this.hasWildcardPrincipal(statement) && !statement.Condition) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Add Condition block to restrict wildcard principal (*) access to the current account only.'
          );
        }
      }
    } catch {
      return null;
    }

    return null;
  }

  private isLogDestinationBucket(resource: TerraformResource, allResources: TerraformResource[]): boolean {
    return allResources.some(r =>
      r.type === 'aws_s3_bucket_logging' &&
      r.values?.target_bucket === resource.values?.bucket
    );
  }

  private hasLoggingConfiguration(resource: TerraformResource, allResources: TerraformResource[]): boolean {
    const bucketId = resource.values?.bucket || resource.address;

    return allResources.some(r =>
      r.type === 'aws_s3_bucket_logging' &&
      (r.values?.bucket === bucketId || r.values?.bucket === resource.values?.id)
    );
  }

  private hasOverlyBroadActions(statement: any): boolean {
    if (!statement.Action) return false;
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    return actions.some((action: string) => action === '*');
  }

  private hasWildcardPrincipal(statement: any): boolean {
    return statement.Principal === '*' ||
      statement.Principal?.AWS === '*' ||
      (Array.isArray(statement.Principal?.AWS) && statement.Principal.AWS.includes('*'));
  }
}

export default new TfS3001Rule();
