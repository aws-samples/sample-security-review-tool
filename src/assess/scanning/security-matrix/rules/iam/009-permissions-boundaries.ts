import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * IAM-009: Compute role with IAM-mutating permissions lacks permissions boundary
 *
 * Roles used by compute resources (Lambda, EC2, ECS, etc.) that can create/modify
 * IAM resources should have a permissions boundary to prevent privilege escalation.
 */
export class Iam009Rule extends BaseRule {
    private static readonly COMPUTE_TYPES = [
        'AWS::Lambda::Function',
        'AWS::EC2::Instance',
        'AWS::ECS::TaskDefinition',
        'AWS::CodeBuild::Project',
        'AWS::Glue::Job',
        'AWS::SageMaker::NotebookInstance'
    ];

    private static readonly ADMIN_POLICIES = new Set([
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/IAMFullAccess',
        'arn:aws:iam::aws:policy/PowerUserAccess'
    ]);

    constructor() {
        super(
            'IAM-009',
            'HIGH',
            'Compute role with IAM-mutating permissions lacks permissions boundary',
            ['AWS::IAM::Role']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const roleId = this.findRoleId(template, resource);
        if (!roleId) return null;
        if (!this.isReferencedByCompute(template, roleId)) return null;
        if (!this.hasIamMutatingPermissions(resource)) return null;
        if (resource.Properties?.PermissionsBoundary) return null;

        return this.createResult(
            stackName,
            template,
            resource,
            this.description,
            'Add PermissionsBoundary to limit IAM resource creation scope'
        );
    }

    private findRoleId(template: Template, resource: Resource): string | null {
        if (!template.Resources) return null;
        return Object.keys(template.Resources).find(key => template.Resources![key] === resource) || null;
    }

    private isReferencedByCompute(template: Template, roleId: string): boolean {
        if (!template.Resources) return false;
        return Object.values(template.Resources).some(r =>
            Iam009Rule.COMPUTE_TYPES.includes(r.Type) && this.resourceReferencesRole(r, roleId)
        );
    }

    private resourceReferencesRole(resource: any, roleId: string): boolean {
        const json = JSON.stringify(resource.Properties || {});
        return json.includes(`"Ref":"${roleId}"`) ||
               json.includes(`"Fn::GetAtt":["${roleId}"`) ||
               json.includes(`"${roleId}"`);
    }

    private hasIamMutatingPermissions(resource: Resource): boolean {
        return this.hasAdminPolicy(resource) || this.hasIamMutatingInlinePolicy(resource);
    }

    private hasAdminPolicy(resource: Resource): boolean {
        const arns = resource.Properties?.ManagedPolicyArns || [];
        return arns.some((arn: any) => typeof arn === 'string' && Iam009Rule.ADMIN_POLICIES.has(arn));
    }

    private hasIamMutatingInlinePolicy(resource: Resource): boolean {
        const policies = resource.Properties?.Policies || [];
        return policies.some((p: any) => this.policyHasIamMutatingActions(p?.PolicyDocument));
    }

    private policyHasIamMutatingActions(doc: any): boolean {
        const statements = Array.isArray(doc?.Statement) ? doc.Statement : [doc?.Statement].filter(Boolean);
        return statements.some((s: any) => s.Effect === 'Allow' && this.hasIamMutatingAction(s.Action));
    }

    private hasIamMutatingAction(actions: any): boolean {
        const list = Array.isArray(actions) ? actions : [actions];
        return list.some((a: any) => typeof a === 'string' && this.isIamMutating(a.toLowerCase()));
    }

    private isIamMutating(action: string): boolean {
        if (action === '*' || action === 'iam:*') return true;
        if (!action.startsWith('iam:')) return false;
        return action.includes('create') || action.includes('attach') || action.includes('put') ||
               action.includes('update') || action.includes('passrole') || action.includes('*');
    }

    public evaluate(_resource: CloudFormationResource, _stackName: string): ScanResult | null {
        return null;
    }
}

export default new Iam009Rule();
