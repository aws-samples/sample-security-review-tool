import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * O2: Restrict admin privileges in AWS Organizations management account to temporary access
 * 
 * Security Principle: Principle of Least Privilege & Temporary Access
 * 
 * This rule ensures that AWS Organizations admin permissions include proper constraints
 * for temporary access and are not granted to IAM users directly.
 * 
 * Risk: Permanent Organizations permissions without constraints enable persistent
 * administrative access without time limits or conditions.
 */
export class O002Rule extends BaseRule {
    constructor() {
        super(
            'ORG-002',
            'HIGH',
            'IAM user has Organizations permissions or role lacks proper access constraints',
            ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        // Check IAM Users - should never have Organizations permissions
        if (resource.Type === 'AWS::IAM::User') {
            if (this.hasOrganizationsPermissions(resource)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Remove Organizations permissions from IAM user. Use IAM roles instead.'
                );
            }
        }

        // Check IAM Roles - should have proper constraints for Organizations permissions
        if (resource.Type === 'AWS::IAM::Role') {
            if (this.hasOrganizationsPermissions(resource) && !this.hasProperAccessConstraints(resource)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Add MFA condition "aws:MultiFactorAuthPresent": "true" to role assume policy.'
                );
            }
        }

        // Check IAM Policies - should not grant Organizations permissions to users
        if (resource.Type === 'AWS::IAM::Policy' || resource.Type === 'AWS::IAM::ManagedPolicy') {
            if (this.hasOrganizationsPermissions(resource) && this.isAttachedToUsers(resource, template)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Remove Organizations permissions from policy attached to users. Use roles instead.'
                );
            }
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private hasOrganizationsPermissions(resource: Resource): boolean {
        const organizationsActions = [
            'organizations:*',
            'organizations:CreateAccount',
            'organizations:CreateOrganization',
            'organizations:DeleteAccount',
            'organizations:DeleteOrganization',
            'organizations:EnableAWSServiceAccess',
            'organizations:DisableAWSServiceAccess',
            'organizations:RegisterDelegatedAdministrator',
            'organizations:DeregisterDelegatedAdministrator'
        ];

        // Check inline policies
        const policies = resource.Properties?.Policies || [];
        for (const policy of policies) {
            if (this.policyHasOrganizationsActions(policy.PolicyDocument, organizationsActions)) {
                return true;
            }
        }

        // Check managed policy ARNs
        const managedPolicies = resource.Properties?.ManagedPolicyArns || [];
        for (const policyArn of managedPolicies) {
            if (typeof policyArn === 'string' && policyArn.includes('Organizations')) {
                return true;
            }
        }

        // Check policy document for managed policies
        if (resource.Properties?.PolicyDocument) {
            return this.policyHasOrganizationsActions(resource.Properties.PolicyDocument, organizationsActions);
        }

        return false;
    }

    private policyHasOrganizationsActions(policyDocument: any, organizationsActions: string[]): boolean {
        if (!policyDocument?.Statement) return false;

        const statements = Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
        
        for (const stmt of statements) {
            if (stmt.Effect === 'Allow' && stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                
                for (const action of actions) {
                    if (organizationsActions.some(orgAction => 
                        action === orgAction || 
                        (orgAction.endsWith('*') && action.startsWith(orgAction.slice(0, -1)))
                    )) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private hasProperAccessConstraints(resource: Resource): boolean {
        const assumeRolePolicy = resource.Properties?.AssumeRolePolicyDocument;
        if (!assumeRolePolicy?.Statement) return false;

        const statements = Array.isArray(assumeRolePolicy.Statement) ? assumeRolePolicy.Statement : [assumeRolePolicy.Statement];
        
        for (const stmt of statements) {
            if (stmt.Effect === 'Allow' && stmt.Condition) {
                // Check for time-based conditions
                if (stmt.Condition.DateLessThan || stmt.Condition.DateGreaterThan) {
                    return true;
                }
                
                // Check for MFA conditions
                if (stmt.Condition.Bool?.['aws:MultiFactorAuthPresent'] === 'true') {
                    return true;
                }
                
                // Check for external ID conditions
                if (stmt.Condition.StringEquals?.['sts:ExternalId']) {
                    return true;
                }
                
                // Check for session duration limits
                if (stmt.Condition.NumericLessThan?.['aws:TokenIssueTime']) {
                    return true;
                }
            }
        }

        return false;
    }

    private isAttachedToUsers(resource: Resource, template: Template): boolean {
        // Check if policy is directly attached to users
        const users = resource.Properties?.Users || [];
        if (users.length > 0) return true;

        // Check if any users in template reference this policy
        if (!template.Resources) return false;

        for (const [, templateResource] of Object.entries(template.Resources)) {
            if (templateResource.Type === 'AWS::IAM::User') {
                const managedPolicies = (templateResource as Resource).Properties?.ManagedPolicyArns || [];
                if (managedPolicies.some((policy: any) => 
                    typeof policy === 'object' && policy.Ref && 
                    policy.Ref === resource.Properties?.PolicyName
                )) {
                    return true;
                }
            }
        }

        return false;
    }
}

export default new O002Rule();