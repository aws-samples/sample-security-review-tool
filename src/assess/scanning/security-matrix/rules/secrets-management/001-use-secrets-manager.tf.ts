import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSec001Rule extends BaseTerraformRule {
  constructor() {
    super('SEC-001', 'HIGH', 'Sensitive data not stored in AWS Secrets Manager', ['aws_lambda_function']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_lambda_function') {
      const envVars = resource.values?.environment?.[0]?.variables || resource.values?.environment?.variables;
      if (!envVars) return null;

      const sensitiveKeywords = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential', 'auth'];

      for (const key of Object.keys(envVars)) {
        const lowerKey = key.toLowerCase();
        if (sensitiveKeywords.some(kw => lowerKey.includes(kw))) {
          const value = envVars[key];
          if (typeof value === 'string' && !value.includes('secretsmanager') && !value.includes('aws_secretsmanager')) {
            return this.createScanResult(resource, projectName, this.description, 'Replace hardcoded sensitive values in Lambda environment variables with references to AWS Secrets Manager.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfSec001Rule();
