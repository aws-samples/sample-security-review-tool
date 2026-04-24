import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-002 Rule: Ensure S3 bucket policies follow least privilege access.
 *
 * Checks that bucket policies do not grant wildcard principals combined with
 * wildcard actions, and that wildcard principals have conditions restricting access.
 */
export class S3002Rule extends BaseRule {
  constructor() {
    super(
      'S3-002',
      'HIGH',
      'S3 bucket policy violates least privilege requirements',
      ['AWS::S3::BucketPolicy']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (resource.Type === 'AWS::S3::BucketPolicy') {
      return this.evaluateBucketPolicy(stackName, template, resource);
    }
    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
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

export default new S3002Rule();
