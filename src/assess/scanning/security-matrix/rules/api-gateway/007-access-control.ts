import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG7 Rule: API GWs must have some form of access control
 * 
 * Documentation: "API GWs must have some form of access control, either authentication or 
 * network-based. If the API is public (or does not limit access by network connectivity) then 
 * API GW must use some form of authentication for callers. If the API does not authenticate callers, 
 * the API GW may not be public."
 * 
 * Note: This rule has been enhanced to handle CDK-generated templates by supporting complex 
 * CloudFormation intrinsic functions like Ref, Fn::GetAtt, and Fn::Sub when resolving 
 * AuthorizationType, RestApiId, and HttpMethod values.
 */
export class ApiGw007Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-007',
      'HIGH',
      'API Gateway lacks proper access control',
      ['AWS::ApiGateway::RestApi', 'AWS::ApiGateway::Method']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::ApiGateway::RestApi') {
      return this.evaluateRestApi(resource, stackName, allResources);
    }

    if (resource.Type === 'AWS::ApiGateway::Method') {
      return this.evaluateMethod(resource, stackName, allResources);
    }

    return null;
  }

  private evaluateRestApi(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // Check if this is a public API
    const isPrivate = this.isPrivateApi(resource.LogicalId, allResources);

    // If it's a private API, it has network-based access control, so it's compliant
    if (isPrivate) {
      return null;
    }

    // If it's a public API, check if all methods have authentication
    const methods = this.getMethodsForApi(resource.LogicalId, allResources);
    const unauthenticatedMethods = methods.filter(method => {
      const authType = this.resolveValue(method.Properties?.AuthorizationType);
      const httpMethod = this.resolveValue(method.Properties?.HttpMethod);

      // Skip OPTIONS methods
      if (httpMethod === 'OPTIONS') {
        return false;
      }

      return !authType || authType === 'NONE';
    });

    if (unauthenticatedMethods.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (public API with ${unauthenticatedMethods.length} unauthenticated methods)`,
        `Either make the API private using EndpointConfiguration.Types=['PRIVATE'] or configure authentication for all methods.`
      );
    }

    return null;
  }

  private evaluateMethod(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // Skip OPTIONS methods
    const httpMethod = this.resolveValue(resource.Properties?.HttpMethod);
    if (httpMethod === 'OPTIONS') {
      return null;
    }

    // Check if authentication is enabled
    const authorizationType = this.resolveValue(resource.Properties?.AuthorizationType);

    // If authentication is enabled, the method has access control
    if (authorizationType && authorizationType !== 'NONE') {
      return null;
    }

    // If authentication is not enabled, check if the API is private
    const restApiId = this.resolveReference(resource.Properties?.RestApiId);
    const isPrivateApi = this.isPrivateApi(restApiId, allResources);

    // If the API is private, the method has network-based access control
    if (isPrivateApi) {
      return null;
    }

    // If the API is public and the method has no authentication, it's a violation
    return this.createScanResult(
      resource,
      stackName,
      `${this.description} (public API method with no authentication)`,
      `Either configure authentication for this method or make the API private.`
    );
  }

  private isPrivateApi(apiId: string | null, resources: CloudFormationResource[]): boolean {
    if (!apiId) {
      return false;
    }

    const api = resources.find(r =>
      r.Type === 'AWS::ApiGateway::RestApi' &&
      r.LogicalId === apiId
    );

    if (!api) {
      return false;
    }

    const endpointConfiguration = api.Properties?.EndpointConfiguration;

    if (endpointConfiguration) {
      const types = this.resolveEndpointTypes(endpointConfiguration.Types);

      if (types && Array.isArray(types) && types.includes('PRIVATE')) {
        return true;
      }
    }

    // Check for policy document that might restrict access
    const policy = api.Properties?.Policy;
    if (policy) {
      // If there's a policy with a VPC condition, it might be restricted to VPC access
      const policyStr = JSON.stringify(policy);
      if (policyStr.includes('aws:SourceVpc') || policyStr.includes('aws:VpcSourceIp')) {
        return true;
      }
    }

    return false;
  }

  private resolveEndpointTypes(types: any): string[] | null {
    if (!types) {
      return null;
    }

    // Handle direct string array
    if (Array.isArray(types)) {
      return types;
    }

    // Handle Ref
    if (typeof types === 'object' && types.Ref) {
      // Can't resolve parameter references directly, assume it could be public
      return ['REGIONAL']; // Default to assuming REGIONAL endpoint
    }

    // Handle Fn::If
    if (typeof types === 'object' && types['Fn::If'] && Array.isArray(types['Fn::If'])) {
      // Take the most permissive option (assume public)
      const options = types['Fn::If'].slice(1);
      for (const option of options) {
        if (Array.isArray(option) && (option.includes('EDGE') || option.includes('REGIONAL'))) {
          return option;
        }
      }
    }

    // Handle single string value
    if (typeof types === 'string') {
      return [types];
    }

    return null;
  }

  private getMethodsForApi(apiId: string, resources: CloudFormationResource[]): CloudFormationResource[] {
    return resources.filter(r =>
      r.Type === 'AWS::ApiGateway::Method' &&
      this.resolveReference(r.Properties?.RestApiId) === apiId
    );
  }

  private resolveReference(ref: any): string | null {
    if (!ref) {
      return null;
    }

    if (typeof ref === 'string') {
      return ref;
    }

    if (typeof ref === 'object') {
      // Handle Ref
      if (ref.Ref) {
        return ref.Ref;
      }

      // Handle Fn::GetAtt - common in CDK templates
      if (ref['Fn::GetAtt'] && Array.isArray(ref['Fn::GetAtt'])) {
        return ref['Fn::GetAtt'][0];
      }

      // Handle Fn::Sub - common in CDK templates
      if (ref['Fn::Sub']) {
        const subValue = ref['Fn::Sub'];
        if (typeof subValue === 'string') {
          // Extract resource name from variable reference like ${ResourceName}
          const matches = subValue.match(/\${([^}]+)}/g);
          if (matches && matches.length === 1) {
            // Return the variable name without ${ and }
            return matches[0].substring(2, matches[0].length - 1);
          }
        }
      }

      // Handle Fn::Join - common in CDK templates
      if (ref['Fn::Join'] && Array.isArray(ref['Fn::Join']) && Array.isArray(ref['Fn::Join'][1])) {
        // Look for Ref or string values in the join array
        for (const element of ref['Fn::Join'][1]) {
          if (typeof element === 'object' && element.Ref) {
            return element.Ref;
          }
          if (typeof element === 'string' && element.trim() !== '') {
            return element;
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
      if (refId.includes('HttpMethod')) {
        return 'GET'; // Default to GET for HTTP method (not OPTIONS)
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
        if (subValue.includes('OPTIONS')) {
          return 'OPTIONS';
        }
      }

      // For other cases, we can't determine the value
      return 'UNKNOWN';
    }

    // For other intrinsic functions or complex expressions, we can't determine the value
    return 'UNKNOWN';
  }
}

export default new ApiGw007Rule();
