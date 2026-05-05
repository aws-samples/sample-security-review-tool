import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG8 Rule: Enable encryption for API Gateway cache
 * 
 * Documentation: "Ensure that stage-level cache encryption is enabled for your Amazon API Gateway APIs."
 * 
 * Note: This requirement is also covered by Checkov rule CKV_AWS_59, which checks if API Gateway 
 * cache encryption is enabled. This rule provides more detailed validation by checking both catch-all 
 * method settings and individual method settings, as well as providing specific remediation guidance.
 */
export class ApiGw008Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-008',
      'HIGH',
      'API Gateway stage cache encryption is not enabled',
      ['AWS::ApiGateway::Stage']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ApiGateway::Stage') {
      // Check if caching is enabled
      const cacheClusterEnabled = this.resolveBooleanValue(resource.Properties?.CacheClusterEnabled);

      // If caching is not enabled, this rule doesn't apply
      if (!cacheClusterEnabled) {
        return null;
      }

      // Check if cache encryption is enabled
      const methodSettings = resource.Properties?.MethodSettings;

      // If no method settings are specified, cache encryption is not configured
      if (!methodSettings || !Array.isArray(methodSettings) || methodSettings.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (cache is enabled but encryption is not configured)`,
          `Add MethodSettings with CacheDataEncrypted set to true.`
        );
      }

      // Check if there's a catch-all method setting with cache encryption enabled
      const catchAllSetting = methodSettings.find(setting => {
        const httpMethod = this.resolveValue(setting.HttpMethod);
        const resourcePath = this.resolveValue(setting.ResourcePath);

        return (httpMethod === '*' || !httpMethod) && (resourcePath === '*' || !resourcePath);
      });

      if (catchAllSetting) {
        const cacheDataEncrypted = this.resolveBooleanValue(catchAllSetting.CacheDataEncrypted);

        if (cacheDataEncrypted !== true) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (catch-all method setting does not enable cache encryption)`,
            `Set CacheDataEncrypted to true in the catch-all method setting.`
          );
        }
      } else {
        // If there's no catch-all setting, check if all methods with caching have encryption enabled
        const methodsWithCaching = methodSettings.filter(setting =>
          this.resolveBooleanValue(setting.CachingEnabled) === true
        );

        if (methodsWithCaching.length > 0) {
          const unencryptedMethods = methodsWithCaching.filter(setting =>
            this.resolveBooleanValue(setting.CacheDataEncrypted) !== true
          );

          if (unencryptedMethods.length > 0) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (${unencryptedMethods.length} methods have caching enabled but not encrypted)`,
              `Set CacheDataEncrypted to true for all methods with caching enabled.`
            );
          }
        } else {
          // If no specific methods have caching enabled, but the stage has caching enabled,
          // we need to ensure there's at least one method setting with cache encryption enabled
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (stage has caching enabled but no method settings configure encryption)`,
            `Add a catch-all method setting with CacheDataEncrypted set to true.`
          );
        }
      }
    }

    return null;
  }

  /**
   * Resolves a value that might be defined using CloudFormation intrinsic functions
   * This is particularly important for CDK-generated templates where values are often
   * defined using Ref, Fn::GetAtt, Fn::Sub, etc.
   */
  private resolveValue(value: any): string | null {
    if (!value) {
      return null;
    }

    // Handle direct string value
    if (typeof value === 'string') {
      return value;
    }

    // Handle Ref
    if (typeof value === 'object' && value.Ref) {
      // We can't resolve parameter references directly, but we can handle some common patterns
      const refId = value.Ref;
      if (refId.includes('HttpMethod')) {
        return '*'; // Default to catch-all for HTTP method
      }
      if (refId.includes('ResourcePath')) {
        return '*'; // Default to catch-all for resource path
      }
      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // Handle Fn::GetAtt
    if (typeof value === 'object' && value['Fn::GetAtt'] && Array.isArray(value['Fn::GetAtt'])) {
      // For GetAtt, we can't determine the actual value
      // Default to a safe value
      return '*';
    }

    // Handle Fn::Sub
    if (typeof value === 'object' && value['Fn::Sub']) {
      const subValue = value['Fn::Sub'];
      if (typeof subValue === 'string') {
        if (subValue.includes('*')) {
          return '*';
        }
      }

      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // For other intrinsic functions or complex expressions, we can't determine the value
    return 'UNKNOWN';
  }

  /**
   * Resolves a boolean value that might be defined using CloudFormation intrinsic functions
   * This is particularly important for CDK-generated templates where values are often
   * defined using Ref, Fn::GetAtt, Fn::Sub, etc.
   */
  private resolveBooleanValue(value: any): boolean | null {
    if (value === undefined || value === null) {
      return null;
    }

    // Handle direct boolean value
    if (typeof value === 'boolean') {
      return value;
    }

    // Handle string value that represents a boolean
    if (typeof value === 'string') {
      return value.toLowerCase() === 'true';
    }

    // Handle Ref
    if (typeof value === 'object' && value.Ref) {
      // We can't resolve parameter references directly, but we can handle some common patterns
      const refId = value.Ref;
      if (refId.includes('Enabled') || refId.includes('Encrypted')) {
        // For parameters with names suggesting they're boolean flags,
        // default to true for security-related parameters
        return true;
      }
      // For other cases, we can't determine the value
      return null;
    }

    // Handle Fn::If - common in CDK templates for conditional values
    if (typeof value === 'object' && value['Fn::If'] && Array.isArray(value['Fn::If'])) {
      // Take the most secure option (true) if one of the options is true
      const options = value['Fn::If'].slice(1);
      for (const option of options) {
        if (option === true) {
          return true;
        }
        if (typeof option === 'string' && option.toLowerCase() === 'true') {
          return true;
        }
      }
      return false;
    }

    // For other intrinsic functions or complex expressions, we can't determine the value
    return null;
  }
}

export default new ApiGw008Rule();
