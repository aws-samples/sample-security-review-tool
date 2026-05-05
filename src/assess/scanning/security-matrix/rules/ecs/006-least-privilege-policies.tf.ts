import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs006Rule extends BaseTerraformRule {
  private static readonly DANGEROUS_MANAGED_POLICIES = ['AdministratorAccess', 'PowerUserAccess'];

  constructor() {
    super(
      'ECS-006',
      'HIGH',
      'ECS task IAM role may not follow least-privilege principle',
      ['aws_ecs_task_definition', 'aws_iam_role']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iam_role') {
      if (!this.isEcsTaskRole(resource, allResources)) return null;

      const inlinePolicies = allResources.filter(r =>
        r.type === 'aws_iam_role_policy' && r.values?.role === resource.values?.name
      );

      const policyAttachments = allResources.filter(r =>
        r.type === 'aws_iam_role_policy_attachment' && r.values?.role === resource.values?.name
      );

      if (inlinePolicies.length === 0 && policyAttachments.length === 0) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Define specific policies for the task role that grant only the permissions required for the task to function.'
        );
      }

      for (const policy of inlinePolicies) {
        const violation = this.validatePolicy(policy);
        if (violation) {
          return this.createScanResult(resource, projectName, this.description, violation);
        }
      }

      for (const attachment of policyAttachments) {
        const arn = attachment.values?.policy_arn;
        if (typeof arn === 'string' && this.isDangerousPolicy(arn)) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Replace broad AWS managed policies with custom policies that grant only the specific permissions required by the task.'
          );
        }
      }
    }

    return null;
  }

  private isEcsTaskRole(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const roleName = role.values?.name;
    const roleArn = role.values?.arn;

    return allResources.some(r =>
      r.type === 'aws_ecs_task_definition' &&
      (r.values?.task_role_arn === roleArn ||
        (typeof r.values?.task_role_arn === 'string' && r.values.task_role_arn.includes(roleName)))
    );
  }

  private validatePolicy(policy: TerraformResource): string | null {
    const policyStr = policy.values?.policy;
    if (typeof policyStr !== 'string') return null;

    try {
      const policyDoc = JSON.parse(policyStr);
      const statements = Array.isArray(policyDoc.Statement) ? policyDoc.Statement : [policyDoc.Statement];

      for (const statement of statements) {
        if (!statement) continue;
        const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

        if (actions.some((a: any) => typeof a === 'string' && (a === '*' || a.endsWith(':*')))) {
          return "Avoid using wildcard actions like '*' or 'service:*'. Specify only the exact actions required by the task.";
        }

        const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
        if (resources.includes('*')) {
          return "Replace wildcard resource '*' with specific ARNs to limit the scope of permissions.";
        }
      }
    } catch {
      return null;
    }

    return null;
  }

  private isDangerousPolicy(arn: string): boolean {
    return TfEcs006Rule.DANGEROUS_MANAGED_POLICIES.some(policy => arn.includes(policy));
  }
}

export default new TfEcs006Rule();
