import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSsm003Rule extends BaseTerraformRule {
  constructor() {
    super('SSM-003', 'HIGH', 'SSM Document parameter may contain sensitive data', ['aws_ssm_document']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ssm_document') {
      const content = resource.values?.content;
      if (!content || typeof content !== 'string') return null;

      let parsed: any;
      try {
        parsed = JSON.parse(content);
      } catch {
        return null;
      }

      const parameters = parsed.parameters || {};
      const sensitivePatterns = [/password/i, /secret/i, /key/i, /token/i, /credential/i, /cert/i, /private/i, /auth/i, /api[_-]?key/i];

      for (const [paramName] of Object.entries(parameters)) {
        if (sensitivePatterns.some(p => p.test(paramName))) {
          return this.createScanResult(resource, projectName, this.description, 'Replace sensitive parameter "' + paramName + '" with a reference to AWS Secrets Manager or SSM Parameter Store SecureString.');
        }
      }
    }

    return null;
  }
}

export default new TfSsm003Rule();
