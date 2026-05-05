import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-005',
      'HIGH',
      'Lambda function IAM role violates principle of least privilege',
      ['aws_iam_role', 'aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iam_role') {
      if (!this.isLambdaRole(resource, allResources)) return null;

      const policyAttachments = allResources.filter(r =>
        r.type === 'aws_iam_role_policy_attachment' &&
        r.values?.role === resource.values?.name
      );

      for (const attachment of policyAttachments) {
        const policyArn = attachment.values?.policy_arn;
        if (typeof policyArn === 'string' && this.isOverlyPermissiveManagedPolicy(policyArn)) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            `Replace overly permissive managed policy '${policyArn}' with a custom policy that grants only the specific permissions required by the Lambda function.`
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
            if (this.hasOverlyPermissiveStatement(policyDoc)) {
              return this.createScanResult(
                resource,
                projectName,
                this.description,
                'Replace wildcard actions with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs.'
              );
            }
          } catch {
            continue;
          }
        }
      }
    }

    return null;
  }

  private isLambdaRole(role: TerraformResource, allResources: TerraformResource[]): boolean {
    const assumeRolePolicy = role.values?.assume_role_policy;
    if (typeof assumeRolePolicy === 'string') {
      try {
        const policy = JSON.parse(assumeRolePolicy);
        const statements = policy.Statement || [];
        for (const statement of statements) {
          const service = statement.Principal?.Service;
          if (service === 'lambda.amazonaws.com' ||
            (Array.isArray(service) && service.includes('lambda.amazonaws.com'))) {
            return true;
          }
        }
      } catch {
        return false;
      }
    }

    const roleName = role.values?.name || role.name || '';
    if (roleName.toLowerCase().includes('lambda')) return true;

    return false;
  }

  private hasOverlyPermissiveStatement(policyDoc: any): boolean {
    const statements = policyDoc.Statement || [];
    for (const statement of statements) {
      if (statement.Effect !== 'Allow') continue;

      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

      for (const action of actions) {
        if (typeof action === 'string' && (action === '*' || action.endsWith(':*'))) {
          if (resources.includes('*')) {
            return true;
          }
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
      'arn:aws:iam::aws:policy/IAMFullAccess',
      'arn:aws:iam::aws:policy/AWSLambdaFullAccess'
    ];
    return overlyPermissive.includes(policyArn) || policyArn.includes('FullAccess');
  }
}

export default new TfLambda005Rule();
