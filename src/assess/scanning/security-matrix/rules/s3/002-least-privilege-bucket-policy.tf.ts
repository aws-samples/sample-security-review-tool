import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfS3002Rule extends BaseTerraformRule {
  constructor() {
    super('S3-002', 'HIGH', 'S3 bucket policy violates least privilege requirements', ['aws_s3_bucket_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const policy = resource.values?.policy;
    if (!policy) return null;

    let policyDoc: any;
    try {
      policyDoc = typeof policy === 'string' ? JSON.parse(policy) : policy;
    } catch {
      return null;
    }

    const statements = policyDoc?.Statement;
    if (!Array.isArray(statements)) return null;

    for (const statement of statements) {
      if (statement.Effect !== 'Allow') continue;

      if (this.hasOverlyBroadActions(statement) && this.hasWildcardPrincipal(statement)) {
        return this.createScanResult(resource, projectName, this.description,
          'Replace wildcard actions (*) with specific S3 actions needed (e.g., s3:GetObject, s3:PutObject).');
      }

      if (this.hasWildcardPrincipal(statement) && !statement.Condition) {
        return this.createScanResult(resource, projectName, this.description,
          'Add a Condition block (e.g., StringEquals aws:SourceAccount) to restrict wildcard principal (*) access.');
      }
    }

    return null;
  }

  private hasOverlyBroadActions(statement: any): boolean {
    if (!statement.Action) return false;
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    return actions.some((action: string) => action === '*');
  }

  private hasWildcardPrincipal(statement: any): boolean {
    return statement.Principal === '*' ||
      statement.Principal?.AWS === '*' ||
      (Array.isArray(statement.Principal?.AWS) && statement.Principal.AWS.includes('*'));
  }
}

export default new TfS3002Rule();
