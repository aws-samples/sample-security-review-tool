import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * SSM-003 Rule: Use non-sensitive data in input parameters.
 * 
 * Documentation: "As a general rule, store credentials, API keys, and certificates in AWS Secrets Manager. 
 * Store configuration data in AWS SSM Parameter Store."
 */
export class SSM003Rule extends BaseRule {
  constructor() {
    super(
      'SSM-003',
      'HIGH',
      'SSM Document parameter may contain sensitive data',
      ['AWS::SSM::Document']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::SSM::Document') {
      return null;
    }

    const contentStr = resource.Properties?.Content;
    if (!contentStr || typeof contentStr !== 'string') {
      return null;
    }

    let content;
    try {
      content = JSON.parse(contentStr);
    } catch {
      return null;
    }

    // Different document types may have different schemas, but parameters structure is common
    const parameters = content.parameters || {};
    const sensitivePatterns = [
      /password/i,
      /passwd/i,
      /secret/i,
      /key/i,
      /token/i,
      /credential/i,
      /cert/i,
      /certificate/i,
      /private/i,
      /auth/i,
      /login/i,
      /username/i,
      /user/i,
      /pass/i,
      /pwd/i,
      /api[_-]?key/i,
      /access[_-]?key/i,
      /session/i,
      /bearer/i,
      /oauth/i,
      /jwt/i,
      /signature/i,
      /hash/i,
      /salt/i,
      /nonce/i
    ];

    for (const [paramName, paramConfig] of Object.entries(parameters)) {
      if (typeof paramConfig === 'object' && paramConfig !== null) {
        const config = paramConfig as any;
        const defaultValue = config.default;
        const description = config.description || '';

        // Check parameter name for sensitive keywords
        const hasSensitiveName = sensitivePatterns.some(pattern => pattern.test(paramName));
        
        // Check if default value looks like sensitive data
        const hasSensitiveDefault = typeof defaultValue === 'string' && 
          (defaultValue.length > 20 || /^[A-Za-z0-9+/=]{20,}$/.test(defaultValue));

        // Check description for sensitive keywords
        const hasSensitiveDescription = sensitivePatterns.some(pattern => pattern.test(description));

        if (hasSensitiveName || hasSensitiveDefault || hasSensitiveDescription) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Replace sensitive parameter '${paramName}' with reference to AWS Secrets Manager or SSM Parameter Store.`
          );
        }
      }
    }

    return null;
  }
}

export default new SSM003Rule();