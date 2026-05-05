import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * B2 Rule: Least-privilege IAM roles for Batch job definitions
 * 
 * When assigning job definition roles, follow the standard security advice of granting least privilege, 
 * or granting only the permissions required to perform a task.
 */
export class Batch002Rule extends BaseRule {
  constructor() {
    super(
      'BATCH-002',
      'HIGH',
      'Batch job definition uses overly permissive IAM roles',
      ['AWS::Batch::JobDefinition']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::Batch::JobDefinition') {
      return this.evaluateJobDefinition(resource, stackName, allResources);
    }
    return null;
  }

  private evaluateJobDefinition(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    const jobRoleArn = resource.Properties?.ContainerProperties?.JobRoleArn;
    if (!jobRoleArn) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add "JobRoleArn": { "Ref": "YourIAMRoleLogicalId" } to ContainerProperties'
      );
    }

    // Find the referenced role
    const role = this.findReferencedRole(jobRoleArn, allResources);
    if (role && this.hasOverlyPermissivePolicies(role)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'In IAM role: 1) Replace "Policies": [{"PolicyDocument": {"Statement": [{"Action": "*", "Resource": "*"}]}}] with "Policies": [{"PolicyDocument": {"Statement": [{"Action": ["s3:GetObject", "s3:PutObject", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": ["arn:aws:s3:::your-bucket/*", "arn:aws:logs:*:*:*"]}]}}]. 2) Remove from "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"] and replace with ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]'
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



  private hasOverlyPermissivePolicies(role: CloudFormationResource): boolean {
    const policies = role.Properties?.Policies || [];
    const managedPolicyArns = role.Properties?.ManagedPolicyArns || [];

    // Check inline policies
    for (const policy of policies) {
      if (this.isPolicyOverlyPermissive(policy.PolicyDocument)) {
        return true;
      }
    }

    // Check managed policies
    const dangerousManagedPolicies = [
      'arn:aws:iam::aws:policy/PowerUserAccess',
      'arn:aws:iam::aws:policy/IAMFullAccess',
      'arn:aws:iam::aws:policy/AdministratorAccess'
    ];

    return managedPolicyArns.some((arn: string) => 
      dangerousManagedPolicies.includes(arn) || arn.includes('*')
    );
  }

  private isPolicyOverlyPermissive(policyDoc: any): boolean {
    if (!policyDoc?.Statement) return false;

    const statements = Array.isArray(policyDoc.Statement) ? policyDoc.Statement : [policyDoc.Statement];
    
    return statements.some((stmt: any) => {
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
      
      // Check for wildcard actions with wildcard resources
      const hasWildcardAction = actions.some((action: string) => action === '*');
      const hasWildcardResource = resources.some((resource: string) => resource === '*');
      
      return hasWildcardAction && hasWildcardResource;
    });
  }
}

export default new Batch002Rule();