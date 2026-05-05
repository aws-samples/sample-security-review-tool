import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * NOTE: This rule (CompLamb002Rule) is the primary rule for checking secure handling of 
 * Lambda environment variables. It validates both variable names AND their values to ensure
 * sensitive data uses secure references to AWS Secrets Manager or Parameter Store.
 * 
 * Rule 013 (CompLamb013Rule) has similar functionality but only checks variable names
 * without validating values. We're keeping this rule (002) as the comprehensive solution
 * and deprecating rule 013 to avoid redundancy.
 * 
 * This rule satisfies requirement L4: "Use AWS Secrets Manager Parameter Store for AWS Lambda
 * function environmental variables. Sensitive data should be encrypted prior to storage in
 * environmental variables or in Secrets Manager. When possible, environmental variables should
 * store Secrets Manager parameters rather than secrets."
 */
export class CompLamb002Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-002',
      'HIGH',
      'Lambda function may contain sensitive data in environment variables',
      ['AWS::Lambda::Function']
    );

    // Regex patterns for sensitive environment variable names
    this.sensitiveNamePatterns = [
      /pass(w(or)?d)?/i,      // password, passwd, pwd
      /secret/i,              // secret
      /(api[-_]?)?key/i,      // key, api_key, apikey, api-key
      /token/i,               // token
      /credential/i,          // credential
      /auth/i,                // auth
      /cert(ificate)?/i,      // cert, certificate
      /private[-_]?key/i,     // private_key, private-key
      /access[-_]?key/i       // access_key, access-key
    ];
  }

  // Regex patterns for sensitive environment variable names
  private sensitiveNamePatterns: RegExp[];

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::Lambda::Function') {
      // Skip if Properties is missing
      if (!resource.Properties) {
        return null;
      }

      const environment = resource.Properties.Environment;
      if (!environment) return null;

      const variables = environment.Variables;
      if (!variables) return null;

      // Check for sensitive variable names
      for (const key in variables) {
        // Check if the variable name matches any sensitive pattern
        if (this.isSensitiveVariableName(key)) {
          // Get the variable value
          const value = variables[key];

          // Check if the value is properly secured
          if (!this.isSecureReference(value, allResources)) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Use AWS Secrets Manager or SSM Parameter Store for sensitive environment variables like '${key}'. Replace direct values with references like '{{resolve:secretsmanager:MySecret:SecretString:password}}' or use dynamic references with Ref or GetAtt.`
            );
          }
        }
      }
    }

    return null;
  }

  /**
   * Check if a variable name appears to contain sensitive information
   */
  private isSensitiveVariableName(name: string): boolean {
    return this.sensitiveNamePatterns.some(pattern => pattern.test(name));
  }

  /**
   * Check if a value is a secure reference (e.g., to Secrets Manager, SSM Parameter Store, etc.)
   */
  private isSecureReference(value: any, allResources?: CloudFormationResource[]): boolean {
    // Check for direct string references to secure services
    if (typeof value === 'string') {
      return this.isStringSecureReference(value);
    }

    // Check for CloudFormation intrinsic functions
    if (typeof value === 'object' && value !== null) {
      return this.isIntrinsicFunctionSecureReference(value, allResources);
    }

    // Default to false for any other type of value
    return false;
  }

  /**
   * Check if a string value is a secure reference
   */
  private isStringSecureReference(value: string): boolean {
    // Check for dynamic references to Secrets Manager
    if (value.includes('{{resolve:secretsmanager:')) {
      return true;
    }

    // Check for dynamic references to SSM Parameter Store secure strings
    if (value.includes('{{resolve:ssm-secure:')) {
      return true;
    }

    // Check for ARN references to secure services
    const secureServicePatterns = [
      /secretsmanager/i,
      /SecretsManager/i,
      /ssm.*parameter/i,
      /parameter.*store/i,
      /kms/i
    ];

    return secureServicePatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if an intrinsic function value is a secure reference
   */
  private isIntrinsicFunctionSecureReference(value: any, allResources?: CloudFormationResource[]): boolean {
    // Check for Ref to a secret resource
    if (value.Ref && typeof value.Ref === 'string') {
      // Check if the referenced resource name suggests it's a secret
      const secureResourcePatterns = [
        /secret/i,
        /password/i,
        /credential/i,
        /key/i,
        /token/i,
        /cert/i,
        /parameter/i
      ];

      if (secureResourcePatterns.some(pattern => pattern.test(value.Ref))) {
        return true;
      }

      // Check if the referenced resource is a Secrets Manager or SSM Parameter resource
      if (allResources) {
        const referencedResource = allResources.find(r => r.LogicalId === value.Ref);
        if (referencedResource) {
          if (referencedResource.Type === 'AWS::SecretsManager::Secret' ||
            referencedResource.Type === 'AWS::SSM::Parameter') {
            return true;
          }
        }
      }
    }

    // Check for GetAtt
    if (value['Fn::GetAtt'] && Array.isArray(value['Fn::GetAtt']) && value['Fn::GetAtt'].length >= 1) {
      const resourceId = value['Fn::GetAtt'][0];

      // Check if the resource name suggests it's a secret
      if (typeof resourceId === 'string') {
        const secureResourcePatterns = [
          /secret/i,
          /password/i,
          /credential/i,
          /key/i,
          /token/i,
          /cert/i,
          /parameter/i
        ];

        if (secureResourcePatterns.some(pattern => pattern.test(resourceId))) {
          return true;
        }

        // Check if the referenced resource is a Secrets Manager or SSM Parameter resource
        if (allResources) {
          const referencedResource = allResources.find(r => r.LogicalId === resourceId);
          if (referencedResource) {
            if (referencedResource.Type === 'AWS::SecretsManager::Secret' ||
              referencedResource.Type === 'AWS::SSM::Parameter') {
              return true;
            }
          }
        }
      }
    }

    // Check for Sub
    if (value['Fn::Sub'] && typeof value['Fn::Sub'] === 'string') {
      const secureServicePatterns = [
        /secretsmanager/i,
        /SecretsManager/i,
        /ssm.*parameter/i,
        /parameter.*store/i,
        /kms/i
      ];

      if (secureServicePatterns.some(pattern => pattern.test(value['Fn::Sub']))) {
        return true;
      }
    }

    // Check for Join
    if (value['Fn::Join'] && Array.isArray(value['Fn::Join']) && value['Fn::Join'].length === 2) {
      const joinParts = value['Fn::Join'][1];
      if (Array.isArray(joinParts)) {
        const joinString = JSON.stringify(joinParts);
        const secureServicePatterns = [
          /secretsmanager/i,
          /SecretsManager/i,
          /ssm.*parameter/i,
          /parameter.*store/i,
          /kms/i,
          /secret/i,
          /password/i,
          /credential/i
        ];

        if (secureServicePatterns.some(pattern => pattern.test(joinString))) {
          return true;
        }
      }
    }

    // Check for ImportValue
    if (value['Fn::ImportValue']) {
      if (typeof value['Fn::ImportValue'] === 'string') {
        const secureResourcePatterns = [
          /secret/i,
          /password/i,
          /credential/i,
          /key/i,
          /token/i,
          /cert/i,
          /parameter/i
        ];

        if (secureResourcePatterns.some(pattern => pattern.test(value['Fn::ImportValue']))) {
          return true;
        }
      } else if (typeof value['Fn::ImportValue'] === 'object') {
        // Recursively check the ImportValue's value
        return this.isIntrinsicFunctionSecureReference(value['Fn::ImportValue'], allResources);
      }
    }

    // Check for other nested intrinsic functions
    const nestedFunctions = ['Fn::FindInMap', 'Fn::If', 'Fn::Select'];
    for (const func of nestedFunctions) {
      if (value[func]) {
        // For these complex functions, we can't easily determine if they reference secure values
        // So we'll assume they might be secure if they contain certain keywords
        const stringValue = JSON.stringify(value[func]);
        const secureKeywords = ['secret', 'password', 'key', 'token', 'credential', 'cert', 'parameter'];
        if (secureKeywords.some(keyword => stringValue.toLowerCase().includes(keyword))) {
          return true;
        }
      }
    }

    return false;
  }
}

export default new CompLamb002Rule();
