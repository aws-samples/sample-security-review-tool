import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * NOTE: This rule (CompLamb013Rule) is deprecated in favor of CompLamb002Rule, which provides
 * more comprehensive validation of secure environment variable usage in Lambda functions.
 * 
 * CompLamb002Rule checks both variable names AND their values, ensuring sensitive data
 * uses secure references to AWS Secrets Manager or Parameter Store.
 * 
 * @deprecated Use CompLamb002Rule instead
 */
export class CompLamb013Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-013',
      'HIGH',
      'Lambda function may store sensitive data in environment variables',
      ['AWS::Lambda::Function']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::Lambda::Function') {
      return null;
    }

    const properties = resource.Properties;
    if (!properties || !properties.Environment || !properties.Environment.Variables) {
      return null;
    }

    const variables = properties.Environment.Variables;

    // Check for environment variable names that might contain sensitive data
    const sensitiveVarPatterns = [
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

    const potentiallySensitiveVars = Object.keys(variables).filter(varName =>
      sensitiveVarPatterns.some(pattern => pattern.test(varName))
    );

    if (potentiallySensitiveVars.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Use AWS Secrets Manager Parameter Store for the following potentially sensitive environment variables: ${potentiallySensitiveVars.join(',')}. Sensitive data should be encrypted prior to storage in environmental variables or in Secrets Manager. When possible, environmental variables should store Secrets Manager parameters rather than secrets.`
      );
    }

    return null;
  }
}

export default new CompLamb013Rule();
