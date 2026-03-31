import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-001 Rule: Ensure that access logging is enabled on all in-scope S3 buckets
 *
 * Documentation: "Access logging enables visibility into actions taken against S3 buckets and objects,
 * and aids in supporting a robust incident response program. Store access logs in a dedicated access
 * log bucket and ensure that only least privilege permissions are granted."
 */
export class S3001Rule extends BaseRule {
  constructor() {
    super(
      'S3-001',
      'HIGH',
      'S3 bucket violates access logging or least privilege requirements',
      ['AWS::S3::Bucket', 'AWS::S3::BucketPolicy']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (resource.Type === 'AWS::S3::Bucket') {
      return this.evaluateBucket(stackName, template, resource);
    }
    if (resource.Type === 'AWS::S3::BucketPolicy') {
      return this.evaluateBucketPolicy(stackName, template, resource);
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
      return this.createResult(stackName, template, resource, this.description, 'Add LoggingConfiguration property to enable S3 access logging with a dedicated log bucket.');
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

  private evaluateBucketPolicy(stackName: string, template: Template, resource: Resource): ScanResult | null {
    const statements = resource.Properties?.PolicyDocument?.Statement;
    if (!statements) return null;

    for (const statement of statements) {
      if (statement.Effect !== 'Allow') continue;

      if (this.hasOverlyBroadActions(statement) && this.hasWildcardPrincipal(statement)) {
        return this.createResult(stackName, template, resource, this.description, 'Replace wildcard actions (*) with specific S3 actions needed (e.g., s3:GetObject, s3:PutObject).');
      }

      if (this.hasUnrestrictedWildcardPrincipal(statement)) {
        return this.createResult(stackName, template, resource, this.description, `Add Condition block 'StringEquals': {'aws:SourceAccount': !Ref 'AWS::AccountId'} to restrict wildcard principal (*) access to current account only.`);
      }
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

      // After cfn-utils parsing, Ref is resolved to the logical ID string
      if (destBucket === logicalId) return true;
      // Raw template format (before parsing)
      if (destBucket?.Ref === logicalId) return true;
      if (destBucket?.['Fn::GetAtt']?.[0] === logicalId) return true;
    }
    return false;
  }

  private isSelfLogging(resource: Resource, destinationBucket: any, logicalId: string): boolean {
    // Check literal bucket name match
    const bucketName = resource.Properties?.BucketName;
    if (typeof bucketName === 'string' && typeof destinationBucket === 'string' && bucketName === destinationBucket) {
      return true;
    }
    // Check Ref to self
    if (destinationBucket?.Ref === logicalId) return true;
    return false;
  }

  private hasUnrestrictedWildcardPrincipal(statement: any): boolean {
    return this.hasWildcardPrincipal(statement) && !statement.Condition;
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

export default new S3001Rule();
