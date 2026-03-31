import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * ECS-006: Is the IAM Role for tasks defined with least-privilege policies?
 *
 * When assigning IAM roles to tasks, follow the standard security advice of granting
 * least privilege - only the permissions required to perform a task. This rule checks
 * that task roles have policies defined and those policies don't use overly permissive
 * wildcards or dangerous managed policies.
 *
 * Note: CDK generates policies as separate AWS::IAM::Policy resources that reference
 * the role via the Roles property, rather than inline on the role itself.
 */
export class Ecs006Rule extends BaseRule {
    private static readonly DANGEROUS_MANAGED_POLICIES = ['AdministratorAccess', 'PowerUserAccess'];
    private static readonly MAX_MANAGED_POLICIES = 3;

    constructor() {
        super(
            'ECS-006',
            'HIGH',
            'ECS task IAM role may not follow least-privilege principle',
            ['AWS::ECS::TaskDefinition', 'AWS::IAM::Role']
        );
    }

    public evaluateResource(_stackName: string, _template: Template, _resource: Resource): ScanResult | null | undefined {
        return undefined; // Cross-resource check required - use legacy evaluate
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!allResources) return null;

        if (resource.Type === 'AWS::ECS::TaskDefinition') {
            return this.evaluateTaskDefinition(resource, stackName, allResources);
        }

        if (resource.Type === 'AWS::IAM::Role') {
            return this.evaluateTaskRole(resource, stackName, allResources);
        }

        return null;
    }

    private evaluateTaskDefinition(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
        const taskRoleArn = resource.Properties?.TaskRoleArn;
        if (!taskRoleArn) return null; // Covered by ECS-005

        const taskRoleId = this.extractRoleLogicalId(taskRoleArn);
        if (!taskRoleId) {
            return this.createScanResult(resource, stackName, this.description,
                'Ensure the TaskRoleArn references an IAM role with least-privilege policies that grant only the permissions required for the task to function.');
        }

        const taskRole = allResources.find(r => r.Type === 'AWS::IAM::Role' && r.LogicalId === taskRoleId);
        if (!taskRole) {
            return this.createScanResult(resource, stackName, this.description,
                'Ensure the TaskRoleArn references an IAM role with least-privilege policies that grant only the permissions required for the task to function.');
        }

        return null;
    }

    private evaluateTaskRole(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
        if (!this.isEcsTaskRole(resource.LogicalId, allResources)) return null;

        const attachedPolicies = this.findAttachedPolicies(resource.LogicalId, allResources);

        if (!this.hasAnyPolicies(resource, attachedPolicies)) {
            return this.createScanResult(resource, stackName, this.description,
                'Define specific policies for the task role that grant only the permissions required for the task to function.');
        }

        const inlinePolicyViolation = this.validateInlinePolicies(resource);
        if (inlinePolicyViolation) {
            return this.createScanResult(resource, stackName, this.description, inlinePolicyViolation);
        }

        const attachedPolicyViolation = this.validateAttachedPolicies(attachedPolicies);
        if (attachedPolicyViolation) {
            return this.createScanResult(resource, stackName, this.description, attachedPolicyViolation);
        }

        const managedPolicyViolation = this.validateManagedPolicies(resource);
        if (managedPolicyViolation) {
            return this.createScanResult(resource, stackName, this.description, managedPolicyViolation);
        }

        return null;
    }

    private extractRoleLogicalId(taskRoleArn: any): string | undefined {
        if (typeof taskRoleArn === 'object' && taskRoleArn['Ref']) {
            return taskRoleArn['Ref'];
        }
        if (typeof taskRoleArn === 'object' && taskRoleArn['Fn::GetAtt']) {
            return taskRoleArn['Fn::GetAtt'][0];
        }
        return undefined;
    }

    private isEcsTaskRole(roleLogicalId: string, allResources: CloudFormationResource[]): boolean {
        return allResources.some(r =>
            r.Type === 'AWS::ECS::TaskDefinition' &&
            r.Properties?.TaskRoleArn &&
            this.roleRefMatches(r.Properties.TaskRoleArn, roleLogicalId)
        );
    }

    private roleRefMatches(taskRoleArn: any, roleLogicalId: string): boolean {
        if (typeof taskRoleArn === 'object' && taskRoleArn['Ref'] === roleLogicalId) return true;
        if (typeof taskRoleArn === 'object' && taskRoleArn['Fn::GetAtt']?.[0] === roleLogicalId) return true;
        return false;
    }

    private findAttachedPolicies(roleLogicalId: string, allResources: CloudFormationResource[]): CloudFormationResource[] {
        return allResources.filter(r =>
            r.Type === 'AWS::IAM::Policy' &&
            this.policyAttachedToRole(r, roleLogicalId)
        );
    }

    private policyAttachedToRole(policy: CloudFormationResource, roleLogicalId: string): boolean {
        const roles = policy.Properties?.Roles;
        if (!Array.isArray(roles)) return false;

        return roles.some((role: any) =>
            (typeof role === 'object' && role['Ref'] === roleLogicalId) ||
            role === roleLogicalId
        );
    }

    private hasAnyPolicies(resource: CloudFormationResource, attachedPolicies: CloudFormationResource[]): boolean {
        const inlinePolicies = resource.Properties?.Policies;
        const managedPolicyArns = resource.Properties?.ManagedPolicyArns;

        const hasInline = Array.isArray(inlinePolicies) && inlinePolicies.length > 0;
        const hasManaged = Array.isArray(managedPolicyArns) && managedPolicyArns.length > 0;
        const hasAttached = attachedPolicies.length > 0;

        return hasInline || hasManaged || hasAttached;
    }

    private validateInlinePolicies(resource: CloudFormationResource): string | null {
        const policies = resource.Properties?.Policies;
        if (!Array.isArray(policies)) return null;

        for (const policy of policies) {
            const violation = this.validatePolicyDocument(policy.PolicyDocument);
            if (violation) return violation;
        }
        return null;
    }

    private validateAttachedPolicies(attachedPolicies: CloudFormationResource[]): string | null {
        for (const policy of attachedPolicies) {
            const violation = this.validatePolicyDocument(policy.Properties?.PolicyDocument);
            if (violation) return violation;
        }
        return null;
    }

    private validatePolicyDocument(policyDocument: any): string | null {
        if (!policyDocument?.Statement) return null;

        const statements = this.normalizeToArray(policyDocument.Statement);

        for (const statement of statements) {
            const actions = this.normalizeToArray(statement.Action);

            if (this.hasWildcardActions(actions)) {
                return "Avoid using wildcard actions like '*' or 'service:*'. Specify only the exact actions required by the task.";
            }

            const resources = this.normalizeToArray(statement.Resource);
            if (this.hasWildcardResources(resources)) {
                return statement.Condition
                    ? "Consider replacing wildcard resource '*' with specific ARNs even when conditions are used, to further limit the scope of permissions."
                    : "Replace wildcard resource '*' with specific ARNs to limit the scope of permissions to only the resources required by the task.";
            }
        }
        return null;
    }

    private validateManagedPolicies(resource: CloudFormationResource): string | null {
        const managedPolicyArns = resource.Properties?.ManagedPolicyArns;
        if (!Array.isArray(managedPolicyArns)) return null;

        if (this.hasOverlyPermissiveManagedPolicy(managedPolicyArns)) {
            return 'Replace broad AWS managed policies with custom policies that grant only the specific permissions required by the task.';
        }

        if (managedPolicyArns.length > Ecs006Rule.MAX_MANAGED_POLICIES) {
            return 'Consider consolidating multiple managed policies into a single custom policy that grants only the specific permissions required by the task.';
        }

        return null;
    }

    private normalizeToArray<T>(value: T | T[]): T[] {
        return Array.isArray(value) ? value : [value];
    }

    private hasWildcardActions(actions: any[]): boolean {
        return actions.some((action: any) =>
            typeof action === 'string' && (action === '*' || action.endsWith(':*'))
        );
    }

    private hasWildcardResources(resources: any[]): boolean {
        return resources.some((resource: any) => resource === '*');
    }

    private hasOverlyPermissiveManagedPolicy(arns: any[]): boolean {
        return arns.some((arn: any) =>
            typeof arn === 'string' &&
            Ecs006Rule.DANGEROUS_MANAGED_POLICIES.some(policy => arn.includes(policy))
        );
    }
}

// Export as both named and default for backwards compatibility
export { Ecs006Rule as ECS006Rule };
export default new Ecs006Rule();
