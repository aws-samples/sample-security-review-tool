import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda012Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-012',
      'HIGH',
      'Lambda function shares an IAM execution role with another function',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const role = resource.values?.role;
    if (!role) return null;

    const lambdaFunctions = allResources.filter(r =>
      r.type === 'aws_lambda_function' && r.values?.role === role
    );

    if (lambdaFunctions.length > 1) {
      const otherFunctions = lambdaFunctions
        .filter(f => f.address !== resource.address)
        .map(f => f.values?.function_name || f.name);

      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Create a unique IAM execution role for this Lambda function instead of sharing with ${otherFunctions.join(', ')}. Lambda functions should have a 1:1 relationship with IAM execution roles.`
      );
    }

    return null;
  }
}

export default new TfLambda012Rule();
