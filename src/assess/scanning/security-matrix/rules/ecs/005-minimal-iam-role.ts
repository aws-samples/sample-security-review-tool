import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ECS5 Rule: Provision tasks with a minimal IAM role
 * 
 * Documentation: "As a general rule, IAM policies should not have '*' for resources. 
 * Strictly speaking that's sometimes necessary, so there should be conditions like tags, 
 * principals, IP addresses, ARNs, or some other limiting clause on an IAM policy if there 
 * is a '*' in the resources attribute."
 * 
 * Note: Some aspects of container privilege are covered by Checkov rule CKV_AWS_97,
 * which checks if ECS Task Definitions are not configured to use privileged containers.
 * This rule adds enhanced checks for IAM role permissions, focusing on the principle of
 * least privilege in IAM policies attached to ECS tasks.
 */
export class ECS005Rule extends BaseRule {
  constructor() {
    super(
      'ECS-005',
      'HIGH',
      'ECS task may have overly permissive IAM roles',
      ['AWS::ECS::TaskDefinition', 'AWS::IAM::Role']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    // For ECS TaskDefinition, check if it has a task role and execution role
    if (resource.Type === 'AWS::ECS::TaskDefinition') {
      const taskRoleArn = resource.Properties?.TaskRoleArn;
      const executionRoleArn = resource.Properties?.ExecutionRoleArn;

      // Check if task role is defined
      if (!taskRoleArn) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Define a TaskRoleArn with minimal permissions required for the task to function.`
        );
      }

      // Check if execution role is defined
      if (!executionRoleArn) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Define an ExecutionRoleArn with minimal permissions required for task execution.`
        );
      }

      // Try to find the referenced roles in the template
      let taskRoleId: string | undefined;
      let executionRoleId: string | undefined;

      // Extract role logical IDs from references
      if (typeof taskRoleArn === 'object' && taskRoleArn['Ref']) {
        taskRoleId = taskRoleArn['Ref'];
      } else if (typeof taskRoleArn === 'object' && taskRoleArn['Fn::GetAtt']) {
        taskRoleId = taskRoleArn['Fn::GetAtt'][0];
      }

      if (typeof executionRoleArn === 'object' && executionRoleArn['Ref']) {
        executionRoleId = executionRoleArn['Ref'];
      } else if (typeof executionRoleArn === 'object' && executionRoleArn['Fn::GetAtt']) {
        executionRoleId = executionRoleArn['Fn::GetAtt'][0];
      }

      // If we couldn't extract the role IDs, we can't check them further
      if (!taskRoleId && !executionRoleId) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure TaskRoleArn and ExecutionRoleArn reference IAM roles with minimal permissions and no wildcard resources without conditions.`
        );
      }
    }

    // For IAM Role, check if it's used by an ECS task and has appropriate permissions
    if (resource.Type === 'AWS::IAM::Role') {
      // Check if this role is used by an ECS task
      const isEcsTaskRole = allResources?.some(r =>
        r.Type === 'AWS::ECS::TaskDefinition' &&
        ((r.Properties?.TaskRoleArn &&
          ((typeof r.Properties.TaskRoleArn === 'object' && r.Properties.TaskRoleArn['Ref'] === resource.LogicalId) ||
            (typeof r.Properties.TaskRoleArn === 'object' && r.Properties.TaskRoleArn['Fn::GetAtt'] && r.Properties.TaskRoleArn['Fn::GetAtt'][0] === resource.LogicalId))) ||
          (r.Properties?.ExecutionRoleArn &&
            ((typeof r.Properties.ExecutionRoleArn === 'object' && r.Properties.ExecutionRoleArn['Ref'] === resource.LogicalId) ||
              (typeof r.Properties.ExecutionRoleArn === 'object' && r.Properties.ExecutionRoleArn['Fn::GetAtt'] && r.Properties.ExecutionRoleArn['Fn::GetAtt'][0] === resource.LogicalId))))
      );

      if (!isEcsTaskRole) {
        return null; // This role is not used by an ECS task, so it's not relevant for this rule
      }

      // Check the role's policies
      const policies = resource.Properties?.Policies;
      const managedPolicyArns = resource.Properties?.ManagedPolicyArns;

      // Check for overly permissive inline policies
      if (policies && Array.isArray(policies)) {
        for (const policy of policies) {
          const policyDocument = policy.PolicyDocument;

          if (!policyDocument || !policyDocument.Statement) {
            continue;
          }

          const statements = Array.isArray(policyDocument.Statement)
            ? policyDocument.Statement
            : [policyDocument.Statement];

          for (const statement of statements) {
            // Check for overly permissive actions
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

            if (actions.includes('*')) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Avoid using wildcard '*' for actions in IAM policies. Specify only the actions required by the task.`
              );
            }

            // Check for overly permissive resources without conditions
            const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

            if (resources.includes('*') && !statement.Condition) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Avoid using wildcard '*' for resources without conditions. Add conditions like tags, principals, IP addresses, or ARNs to limit the scope.`
              );
            }
          }
        }
      }

      // Check for potentially overly permissive managed policies
      if (managedPolicyArns && Array.isArray(managedPolicyArns)) {
        const potentiallyOverlyPermissivePolicies = managedPolicyArns.filter(arn =>
          typeof arn === 'string' && (
            arn.includes('AdministratorAccess') ||
            arn.includes('PowerUserAccess') ||
            arn.includes('FullAccess')
          )
        );

        if (potentiallyOverlyPermissivePolicies.length > 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Avoid using overly permissive managed policies like AdministratorAccess or FullAccess. Create custom policies with only the permissions required by the task.`
          );
        }
      }
    }

    return null;
  }
}

export default new ECS005Rule();
