import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG4 Rule: Implement authentication for API Gateway
 * 
 * Documentation: "Each API needs to have an authentication and authorization implementation strategy. 
 * This includes using such approaches as IAM, Cognito User Pools, Custom authorizer, etc."
 * 
 * Note: This rule has been enhanced to handle CDK-generated templates by supporting complex 
 * CloudFormation intrinsic functions like Ref, Fn::GetAtt, and Fn::Sub when resolving 
 * AuthorizationType and HttpMethod values.
 */
export class ApiGw004Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-004',
      'HIGH',
      'API Gateway lacks proper authentication configuration',
      ['AWS::ApiGateway::Method']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ApiGateway::Method') {
      // Check if this is a public API method (not OPTIONS)
      const httpMethod = this.resolveValue(resource.Properties?.HttpMethod);

      if (httpMethod !== 'OPTIONS') {
        // Check if authentication is enabled
        const authorizationType = this.resolveValue(resource.Properties?.AuthorizationType);

        // If AuthorizationType is not specified or set to NONE, authentication is not enabled
        if (!authorizationType || authorizationType === 'NONE') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (AuthorizationType is ${authorizationType || 'not specified'})`,
            `Set AuthorizationType to 'AWS_IAM', 'COGNITO_USER_POOLS', or 'CUSTOM' and configure appropriate authorization settings.`
          );
        }

        // If AuthorizationType is CUSTOM or COGNITO_USER_POOLS, check if the authorizer is configured correctly
        if (authorizationType === 'CUSTOM' || authorizationType === 'COGNITO_USER_POOLS') {
          const authorizerId = resource.Properties?.AuthorizerId;

          // Check if AuthorizerId is specified (either directly or via intrinsic functions)
          if (!authorizerId) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (${authorizationType} specified but AuthorizerId is missing)`,
              `Add AuthorizerId referencing an AWS::ApiGateway::Authorizer resource.`
            );
          }

          // For complex references, we can't fully validate the authorizer ID,
          // but we can at least check that something is provided
          const resolvedAuthorizerId = this.resolveValue(authorizerId);
          if (resolvedAuthorizerId === null || resolvedAuthorizerId === 'UNKNOWN') {
            // We don't fail here because the reference might be valid even if we can't resolve it
            // Just log a warning in the future if needed
          }
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
      if (refId.includes('Authorizer')) {
        return 'CUSTOM'; // Assume it's a custom authorizer
      }
      if (refId.includes('Cognito')) {
        return 'COGNITO_USER_POOLS'; // Assume it's a Cognito authorizer
      }
      if (refId.includes('IAM')) {
        return 'AWS_IAM'; // Assume it's IAM authorization
      }
      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // Handle Fn::GetAtt
    if (typeof value === 'object' && value['Fn::GetAtt'] && Array.isArray(value['Fn::GetAtt'])) {
      const getAtt = value['Fn::GetAtt'];
      const resourceId = getAtt[0];
      const attribute = getAtt[1];

      if (resourceId.includes('Authorizer')) {
        return 'CUSTOM'; // Assume it's a custom authorizer
      }
      if (resourceId.includes('Cognito')) {
        return 'COGNITO_USER_POOLS'; // Assume it's a Cognito authorizer
      }

      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // Handle Fn::Sub
    if (typeof value === 'object' && value['Fn::Sub']) {
      const subValue = value['Fn::Sub'];
      if (typeof subValue === 'string') {
        if (subValue.includes('CUSTOM') || subValue.includes('Authorizer')) {
          return 'CUSTOM';
        }
        if (subValue.includes('COGNITO') || subValue.includes('UserPool')) {
          return 'COGNITO_USER_POOLS';
        }
        if (subValue.includes('AWS_IAM') || subValue.includes('IAM')) {
          return 'AWS_IAM';
        }
      }

      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // For other intrinsic functions or complex expressions, we can't determine the value
    return 'UNKNOWN';
  }
}

export default new ApiGw004Rule();
