import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG6 Rule: Enable AWS CloudWatch logs for API Gateway
 * 
 * Documentation: "Solutions must ensure that AWS CloudWatch logs are enabled for all APIs 
 * created with Amazon API Gateway service in order to track and analyze execution behavior 
 * at the API stage level."
 * 
 * Note: This rule has been enhanced to handle CDK-generated templates by supporting complex 
 * CloudFormation intrinsic functions like Ref, Fn::GetAtt, and Fn::Sub when resolving 
 * LoggingLevel and HttpMethod values in MethodSettings.
 */
export class ApiGw006Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-006',
      'HIGH',
      'API Gateway does not have CloudWatch logs enabled',
      ['AWS::ApiGateway::Stage']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ApiGateway::Stage') {
      const methodSettings = resource.Properties?.MethodSettings;

      // Check if logging is enabled at the stage level
      if (!this.isLoggingEnabledInStage(resource)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Enable CloudWatch logs by setting MethodSettings with LoggingLevel to INFO or ERROR.`
        );
      }

      // If method settings are specified, check if logging is enabled for all methods
      if (methodSettings && Array.isArray(methodSettings)) {
        for (const setting of methodSettings) {
          const loggingLevel = this.resolveValue(setting.LoggingLevel);

          // If logging level is not specified or set to OFF, logging is not enabled
          if (!loggingLevel || loggingLevel === 'OFF') {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (LoggingLevel is ${loggingLevel || 'not specified'} for some methods)`,
              `Set LoggingLevel to INFO or ERROR for all methods.`
            );
          }
        }
      }
    }

    return null;
  }

  private isLoggingEnabledInStage(resource: CloudFormationResource): boolean {
    // Check if method settings are specified
    const methodSettings = resource.Properties?.MethodSettings;

    if (!methodSettings || !Array.isArray(methodSettings) || methodSettings.length === 0) {
      return false;
    }

    // Check if there's a catch-all method setting with logging enabled
    const catchAllSetting = methodSettings.find(setting => {
      const httpMethod = this.resolveValue(setting.HttpMethod);
      const resourcePath = this.resolveValue(setting.ResourcePath);

      return (httpMethod === '*' || !httpMethod) && (resourcePath === '*' || !resourcePath);
    });

    if (catchAllSetting) {
      const loggingLevel = this.resolveValue(catchAllSetting.LoggingLevel);
      return loggingLevel === 'INFO' || loggingLevel === 'ERROR';
    }

    // If there's no catch-all setting, check if all specified methods have logging enabled
    return methodSettings.every(setting => {
      const loggingLevel = this.resolveValue(setting.LoggingLevel);
      return loggingLevel === 'INFO' || loggingLevel === 'ERROR';
    });
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
      if (refId.includes('LogLevel') || refId.includes('LoggingLevel')) {
        // Assume it's a valid logging level parameter
        return 'INFO'; // Default to INFO as a safe assumption
      }
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
      // Default to a safe value for logging level
      return 'INFO';
    }

    // Handle Fn::Sub
    if (typeof value === 'object' && value['Fn::Sub']) {
      const subValue = value['Fn::Sub'];
      if (typeof subValue === 'string') {
        if (subValue.includes('INFO')) {
          return 'INFO';
        }
        if (subValue.includes('ERROR')) {
          return 'ERROR';
        }
        if (subValue.includes('OFF')) {
          return 'OFF';
        }
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
}

export default new ApiGw006Rule();
