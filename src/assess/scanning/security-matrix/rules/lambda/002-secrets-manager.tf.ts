import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda002Rule extends BaseTerraformRule {
  private sensitiveNamePatterns: RegExp[] = [
    /pass(w(or)?d)?/i,
    /secret/i,
    /(api[-_]?)?key/i,
    /token/i,
    /credential/i,
    /auth/i,
    /cert(ificate)?/i,
    /private[-_]?key/i,
    /access[-_]?key/i
  ];

  constructor() {
    super(
      'LAMBDA-002',
      'HIGH',
      'Lambda function may contain sensitive data in environment variables',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const environment = resource.values?.environment;
    if (!environment || !Array.isArray(environment) || environment.length === 0) return null;

    const variables = environment[0]?.variables;
    if (!variables || typeof variables !== 'object') return null;

    for (const key of Object.keys(variables)) {
      if (this.isSensitiveVariableName(key)) {
        const value = variables[key];
        if (!this.isSecureReference(value)) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            `Use AWS Secrets Manager or SSM Parameter Store for sensitive environment variables like '${key}'. Replace direct values with data source references.`
          );
        }
      }
    }

    return null;
  }

  private isSensitiveVariableName(name: string): boolean {
    return this.sensitiveNamePatterns.some(pattern => pattern.test(name));
  }

  private isSecureReference(value: any): boolean {
    if (typeof value !== 'string') return true;

    const securePatterns = [
      /secretsmanager/i,
      /ssm/i,
      /arn:aws:secretsmanager/i,
      /arn:aws:ssm/i,
      /parameter.*store/i
    ];

    return securePatterns.some(pattern => pattern.test(value));
  }
}

export default new TfLambda002Rule();
