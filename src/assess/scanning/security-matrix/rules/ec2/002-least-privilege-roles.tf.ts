import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEc2002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EC2-002',
      'HIGH',
      'EC2 instance role violates principle of least privilege',
      ['aws_instance', 'aws_iam_role']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_instance') {
      const iamInstanceProfile = resource.values?.iam_instance_profile;
      if (!iamInstanceProfile) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Attach an IAM instance profile with minimal permissions (at least CloudWatch Logs and Systems Manager access) to the EC2 instance.'
        );
      }
    }

    if (resource.type === 'aws_iam_role') {
      if (!this.isEc2Role(resource, allResources)) {
        return null;
      }

      const result = this.checkRolePermissions(resource, projectName, allResources);
      if (result) return result;
    }

    return null;
  }

  private isEc2Role(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const assumeRolePolicy = role.values?.assume_role_policy;
    if (typeof assumeRolePolicy === 'string') {
      try {
        const policy = JSON.parse(assumeRolePolicy);
        const statements = policy.Statement || [];
        for (const statement of statements) {
          const service = statement.Principal?.Service;
          if (service === 'ec2.amazonaws.com' ||
            (Array.isArray(service) && service.includes('ec2.amazonaws.com'))) {
            return true;
          }
        }
      } catch {
        return false;
      }
    }

    const roleName = role.values?.name || role.name;
    if (typeof roleName === 'string' && roleName.toLowerCase().includes('ec2')) {
      return true;
    }

    return false;
  }

  private checkRolePermissions(role: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const managedPolicyArns = this.getManagedPolicies(role, allResources);

    for (const arn of managedPolicyArns) {
      if (this.isOverlyPermissiveManagedPolicy(arn)) {
        return this.createScanResult(
          role,
          projectName,
          this.description,
          'Replace the overly permissive managed policy with a custom policy that grants only the specific permissions required by the EC2 instance.'
        );
      }
    }

    const inlinePolicies = this.getInlinePolicies(role, allResources);
    for (const policyDoc of inlinePolicies) {
      if (this.hasOverlyPermissiveStatement(policyDoc)) {
        return this.createScanResult(
          role,
          projectName,
          this.description,
          'Modify the IAM policy to follow the principle of least privilege by replacing wildcard actions with specific actions and restricting resources.'
        );
      }
    }

    return null;
  }

  private getManagedPolicies(role: TerraformResource, allResources: TerraformResource[]): string[] {
    const attachments = allResources.filter(r =>
      r.type === 'aws_iam_role_policy_attachment' &&
      r.values?.role === role.values?.name
    );

    return attachments
      .map(a => a.values?.policy_arn)
      .filter((arn): arn is string => typeof arn === 'string');
  }

  private getInlinePolicies(role: TerraformResource, allResources: TerraformResource[]): any[] {
    const policies = allResources.filter(r =>
      r.type === 'aws_iam_role_policy' &&
      r.values?.role === role.values?.name
    );

    const docs: any[] = [];
    for (const policy of policies) {
      const policyStr = policy.values?.policy;
      if (typeof policyStr === 'string') {
        try {
          docs.push(JSON.parse(policyStr));
        } catch {
          continue;
        }
      }
    }
    return docs;
  }

  private hasOverlyPermissiveStatement(policyDoc: any): boolean {
    const statements = policyDoc.Statement || [];
    for (const statement of statements) {
      if (statement.Effect !== 'Allow') continue;

      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

      for (const action of actions) {
        if ((action === '*' || (typeof action === 'string' && action.endsWith('*'))) && resources.includes('*')) {
          return true;
        }
      }
    }
    return false;
  }

  private isOverlyPermissiveManagedPolicy(policyArn: string): boolean {
    const overlyPermissive = [
      'arn:aws:iam::aws:policy/AdministratorAccess',
      'arn:aws:iam::aws:policy/PowerUserAccess',
      'arn:aws:iam::aws:policy/AmazonS3FullAccess',
      'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
      'arn:aws:iam::aws:policy/AmazonRDSFullAccess',
      'arn:aws:iam::aws:policy/AmazonEC2FullAccess',
      'arn:aws:iam::aws:policy/IAMFullAccess'
    ];
    return overlyPermissive.includes(policyArn);
  }
}

export default new TfEc2002Rule();
