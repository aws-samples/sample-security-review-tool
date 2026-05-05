import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ECS-005',
      'HIGH',
      'ECS task may have overly permissive IAM roles',
      ['aws_ecs_task_definition', 'aws_iam_role']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ecs_task_definition') {
      const taskRoleArn = resource.values?.task_role_arn;
      if (!taskRoleArn) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Define a task_role_arn with minimal permissions required for the task to function.'
        );
      }

      const executionRoleArn = resource.values?.execution_role_arn;
      if (!executionRoleArn) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Define an execution_role_arn with minimal permissions required for task execution.'
        );
      }
    }

    if (resource.type === 'aws_iam_role') {
      if (!this.isEcsTaskRole(resource, allResources)) return null;

      const policyAttachments = allResources.filter(r =>
        r.type === 'aws_iam_role_policy_attachment' &&
        r.values?.role === resource.values?.name
      );

      for (const attachment of policyAttachments) {
        const policyArn = attachment.values?.policy_arn;
        if (typeof policyArn === 'string' && this.isOverlyPermissive(policyArn)) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Avoid using overly permissive managed policies like AdministratorAccess or FullAccess. Create custom policies with only the permissions required by the task.'
          );
        }
      }

      const inlinePolicies = allResources.filter(r =>
        r.type === 'aws_iam_role_policy' &&
        r.values?.role === resource.values?.name
      );

      for (const policy of inlinePolicies) {
        const policyStr = policy.values?.policy;
        if (typeof policyStr === 'string') {
          try {
            const policyDoc = JSON.parse(policyStr);
            const statements = policyDoc.Statement || [];
            for (const statement of statements) {
              if (statement.Effect !== 'Allow') continue;
              const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
              if (actions.includes('*')) {
                return this.createScanResult(
                  resource,
                  projectName,
                  this.description,
                  "Avoid using wildcard '*' for actions in IAM policies. Specify only the actions required by the task."
                );
              }
              const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
              if (resources.includes('*') && !statement.Condition) {
                return this.createScanResult(
                  resource,
                  projectName,
                  this.description,
                  "Avoid using wildcard '*' for resources without conditions. Add conditions to limit the scope."
                );
              }
            }
          } catch {
            continue;
          }
        }
      }
    }

    return null;
  }

  private isEcsTaskRole(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const roleArn = role.values?.arn;
    const roleName = role.values?.name;

    return allResources.some(r =>
      r.type === 'aws_ecs_task_definition' &&
      (r.values?.task_role_arn === roleArn ||
        r.values?.execution_role_arn === roleArn ||
        (typeof r.values?.task_role_arn === 'string' && r.values.task_role_arn.includes(roleName)) ||
        (typeof r.values?.execution_role_arn === 'string' && r.values.execution_role_arn.includes(roleName)))
    );
  }

  private isOverlyPermissive(policyArn: string): boolean {
    return policyArn.includes('AdministratorAccess') ||
      policyArn.includes('PowerUserAccess') ||
      policyArn.includes('FullAccess');
  }
}

export default new TfEcs005Rule();
