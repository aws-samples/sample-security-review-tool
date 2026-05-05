import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CB9 Rule: Include s3:GetBucketAcl and s3:GetBucketLocation permissions in AWS CodeBuild IAM roles
 * 
 * Secure access to S3 buckets is important to ensure confidentiality and integrity with CodeBuild.
 */
export class CodeBuild009Rule extends BaseRule {
  constructor() {
    super(
      'CODEBUILD-009',
      'HIGH',
      'CodeBuild IAM role missing required S3 bucket permissions',
      ['AWS::CodeBuild::Project']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    const serviceRole = resource.Properties?.ServiceRole;
    if (!serviceRole) {
      return null;
    }

    const role = this.findReferencedRole(serviceRole, allResources);
    if (!role) {
      return null;
    }

    const hasRequiredPermissions = this.hasRequiredS3Permissions(role);
    if (!hasRequiredPermissions) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add S3 permissions to CodeBuild service role: "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:GetObject", "s3:PutObject"] with appropriate "Resource" ARNs'
      );
    }

    return null;
  }

  private findReferencedRole(roleRef: any, resources: CloudFormationResource[]): CloudFormationResource | null {
    if (typeof roleRef === 'object' && roleRef.Ref) {
      return resources.find(r => r.Type === 'AWS::IAM::Role' && r.LogicalId === roleRef.Ref) || null;
    }
    return null;
  }

  private hasRequiredS3Permissions(role: CloudFormationResource): boolean {
    const policies = role.Properties?.Policies || [];
    const managedPolicyArns = role.Properties?.ManagedPolicyArns || [];

    // Check for CodeBuild service managed policy
    const hasCodeBuildPolicy = managedPolicyArns.some((arn: string) => 
      arn.includes('CodeBuildDeveloperAccess') || arn.includes('AWSCodeBuildDeveloperAccess')
    );

    if (hasCodeBuildPolicy) {
      return true;
    }

    // Check inline policies for required S3 permissions
    for (const policy of policies) {
      if (this.policyHasRequiredS3Permissions(policy.PolicyDocument)) {
        return true;
      }
    }

    return false;
  }

  private policyHasRequiredS3Permissions(policyDoc: any): boolean {
    if (!policyDoc?.Statement) return false;

    const statements = Array.isArray(policyDoc.Statement) ? policyDoc.Statement : [policyDoc.Statement];
    const requiredActions = ['s3:GetBucketAcl', 's3:GetBucketLocation'];

    return statements.some((stmt: any) => {
      if (stmt.Effect !== 'Allow') return false;
      
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      return requiredActions.every(required => 
        actions.some((action: string) => action === required || action === 's3:*' || action === '*')
      );
    });
  }
}

export default new CodeBuild009Rule();