import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda013Rule extends BaseTerraformRule {
  private sensitiveVarPatterns: RegExp[] = [
    /key/i,
    /secret/i,
    /password/i,
    /pwd/i,
    /token/i,
    /credential/i,
    /auth/i,
    /api[-_]?key/i,
    /access[-_]?key/i
  ];

  constructor() {
    super(
      'LAMBDA-013',
      'HIGH',
      'Lambda function may store sensitive data in environment variables',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const environment = resource.values?.environment;
    if (!environment || !Array.isArray(environment) || environment.length === 0) return null;

    const variables = environment[0]?.variables;
    if (!variables || typeof variables !== 'object') return null;

    const potentiallySensitiveVars = Object.keys(variables).filter(varName =>
      this.sensitiveVarPatterns.some(pattern => pattern.test(varName))
    );

    if (potentiallySensitiveVars.length > 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Use AWS Secrets Manager or SSM Parameter Store for the following potentially sensitive environment variables: ${potentiallySensitiveVars.join(', ')}.`
      );
    }

    return null;
  }
}

export default new TfLambda013Rule();
