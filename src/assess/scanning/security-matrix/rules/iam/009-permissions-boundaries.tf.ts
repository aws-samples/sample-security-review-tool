import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIam009Rule extends BaseTerraformRule {
  private static readonly COMPUTE_TYPES = [
    'aws_lambda_function',
    'aws_instance',
    'aws_ecs_task_definition',
    'aws_codebuild_project',
    'aws_glue_job',
    'aws_sagemaker_notebook_instance'
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
      ['aws_iam_role']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_iam_role') return null;

    if (!this.isReferencedByCompute(resource, allResources)) return null;
    if (!this.hasIamMutatingPermissions(resource, allResources)) return null;
    if (resource.values?.permissions_boundary) return null;

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      'Add permissions_boundary to limit IAM resource creation scope.'
    );
  }

  private isReferencedByCompute(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const roleArn = role.values?.arn;
    const roleName = role.values?.name;

    return allResources.some(r => {
      if (!TfIam009Rule.COMPUTE_TYPES.includes(r.type)) return false;
      const resourceJson = JSON.stringify(r.values || {});
      return (roleArn && resourceJson.includes(roleArn)) ||
        (roleName && resourceJson.includes(roleName));
    });
  }

  private hasIamMutatingPermissions(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const roleName = role.values?.name;

    const policyAttachments = allResources.filter(r =>
      r.type === 'aws_iam_role_policy_attachment' && r.values?.role === roleName
    );

    for (const attachment of policyAttachments) {
      const arn = attachment.values?.policy_arn;
      if (typeof arn === 'string' && TfIam009Rule.ADMIN_POLICIES.has(arn)) {
        return true;
      }
    }

    const inlinePolicies = allResources.filter(r =>
      r.type === 'aws_iam_role_policy' && r.values?.role === roleName
    );

    for (const policy of inlinePolicies) {
      const policyStr = policy.values?.policy;
      if (typeof policyStr !== 'string') continue;

      try {
        const doc = JSON.parse(policyStr);
        const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement].filter(Boolean);

        for (const statement of statements) {
          if (statement.Effect !== 'Allow') continue;
          const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

          for (const action of actions) {
            if (typeof action === 'string' && this.isIamMutating(action.toLowerCase())) {
              return true;
            }
          }
        }
      } catch {
        continue;
      }
    }

    return false;
  }

  private isIamMutating(action: string): boolean {
    if (action === '*' || action === 'iam:*') return true;
    if (!action.startsWith('iam:')) return false;
    return action.includes('create') || action.includes('attach') || action.includes('put') ||
      action.includes('update') || action.includes('passrole') || action.includes('*');
  }
}

export default new TfIam009Rule();
