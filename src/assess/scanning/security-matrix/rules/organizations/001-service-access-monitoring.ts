import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * O1: Enable AWS Organizations service access according to least-privilege
 * 
 * Security Principle: Principle of Least Privilege
 * 
 * This rule ensures that Organizations resources are configured with proper
 * access controls and SCPs to prevent unauthorized service access.
 * 
 * Risk: Without proper SCPs and access controls, services may gain unauthorized
 * access to organization hierarchy, membership, and OU structure.
 */
export class O001Rule extends BaseRule {
    constructor() {
        super(
            'ORG-001',
            'HIGH',
            'Organizations lacks proper Service Control Policies (SCPs) to restrict service access',
            ['AWS::Organizations::Organization', 'AWS::Organizations::Policy']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        // Check Organizations with ALL features but no restrictive SCPs
        if (resource.Type === 'AWS::Organizations::Organization') {
            const featureSet = resource.Properties?.FeatureSet || 'ALL';
            if (featureSet === 'ALL' && !this.hasRestrictiveServiceControlPolicies(template)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Add Service Control Policy with deny statements for organizations:EnableAWSServiceAccess and organizations:DisableAWSServiceAccess actions.'
                );
            }
            return null;
        }

        // Check SCPs for proper service access restrictions
        if (resource.Type === 'AWS::Organizations::Policy') {
            const policyType = resource.Properties?.Type;
            if (policyType === 'SERVICE_CONTROL_POLICY' && !this.hasProperServiceAccessRestrictions(resource)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Add deny statements for organizations:EnableAWSServiceAccess and organizations:DisableAWSServiceAccess actions to Service Control Policy.'
                );
            }
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private hasRestrictiveServiceControlPolicies(template: Template): boolean {
        if (!template.Resources) return false;

        return Object.values(template.Resources).some((resource: any) => 
            resource.Type === 'AWS::Organizations::Policy' &&
            resource.Properties?.Type === 'SERVICE_CONTROL_POLICY' &&
            this.hasProperServiceAccessRestrictions(resource as Resource)
        );
    }

    private hasProperServiceAccessRestrictions(resource: Resource): boolean {
        const policyDocument = resource.Properties?.PolicyDocument;
        if (!policyDocument?.Statement) return false;

        const statements = Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
        
        // Look for deny statements that restrict service access actions
        const restrictedActions = [
            'organizations:EnableAWSServiceAccess',
            'organizations:DisableAWSServiceAccess'
        ];

        return statements.some((stmt: any) => {
            if (stmt.Effect !== 'Deny') return false;
            
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            
            // Check if any restricted actions are denied
            return restrictedActions.some(restrictedAction =>
                actions.some((action: string) => 
                    action === restrictedAction ||
                    action === 'organizations:*' ||
                    action === '*'
                )
            );
        });
    }
}

export default new O001Rule();