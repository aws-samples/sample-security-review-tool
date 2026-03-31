import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * IdC6: Assign IAM permission sets according to the principle of least privilege
 * 
 * Security Principle: Principle of Least Privilege
 * 
 * This rule ensures that Identity Center permission sets are configured with
 * least privilege permissions and appropriate session duration limits.
 * 
 * Risk: Overly permissive permission sets enable privilege escalation and
 * persistent access beyond necessary scope.
 */
export class IdC006Rule extends BaseRule {
    constructor() {
        super(
            'IdC-006',
            'HIGH',
            'Identity Center permission set violates least privilege principle',
            ['AWS::SSO::PermissionSet']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const issues: string[] = [];

        // Check session duration - should be 8 hours or less
        const sessionDuration = resource.Properties?.SessionDuration;
        if (this.exceedsMaxDuration(sessionDuration)) {
            issues.push('Set SessionDuration to PT8H');
        }

        // Check for overly broad managed policies
        const managedPolicies = resource.Properties?.ManagedPolicyArns || [];
        const dangerousPolicies = managedPolicies.filter((policy: string) => 
            typeof policy === 'string' && this.isDangerousPolicy(policy)
        );
        
        if (dangerousPolicies.length > 0) {
            issues.push(`Replace overly broad managed policies with specific policies`);
        }

        // Check inline policy for wildcard permissions
        const inlinePolicy = resource.Properties?.InlinePolicy;
        if (inlinePolicy && this.hasWildcardPermissions(inlinePolicy)) {
            issues.push('Replace wildcard permissions (*) with specific actions and resources');
        }

        if (issues.length > 0) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                issues.join('. ') + '.'
            );
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private exceedsMaxDuration(duration: string | undefined): boolean {
        if (!duration) return true; 
        
        // Parse ISO 8601 duration format (PT8H = 8 hours)
        const match = duration.match(/^PT(\d+)H$/);
        if (!match) return true; // Invalid format, flag it
        
        const hours = parseInt(match[1], 10);
        return hours > 8;
    }

    private isDangerousPolicy(policyArn: string): boolean {
        const dangerousPatterns = [
            'AdministratorAccess',
            'PowerUserAccess', 
            'FullAccess',
            'IAMFullAccess',
            'SecurityAudit' 
        ];
        
        return dangerousPatterns.some(pattern => policyArn.includes(pattern));
    }

    private hasWildcardPermissions(inlinePolicy: any): boolean {
        if (!inlinePolicy?.PolicyDocument?.Statement) return false;

        const statements = Array.isArray(inlinePolicy.PolicyDocument.Statement) 
            ? inlinePolicy.PolicyDocument.Statement 
            : [inlinePolicy.PolicyDocument.Statement];

        return statements.some((stmt: any) => {
            if (stmt.Effect !== 'Allow') return false;
            
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
            
            return actions.some((action: string) => action === '*') ||
                   resources.some((resource: string) => resource === '*');
        });
    }
}

export default new IdC006Rule();