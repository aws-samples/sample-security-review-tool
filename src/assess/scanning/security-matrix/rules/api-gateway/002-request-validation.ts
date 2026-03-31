import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG2 Rule: Activate request validation on API Gateway endpoints
 * 
 * Documentation: "The API should have basic request validation enabled. If the API is integrated 
 * with custom source (Lambda, ECS, etc..) in the backend, deeper input validation should be 
 * considered for implementation."
 */
export class ApiGw002Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-002',
      'HIGH',
      'API Gateway has method(s) without request validation',
      ['AWS::ApiGateway::RestApi', 'AWS::ApiGateway::RequestValidator']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::ApiGateway::RestApi') {
      const methodsWithoutValidation = this.collectMethodsWithoutValidation(allResources);
      return this.evaluateRestApi(resource, stackName, methodsWithoutValidation);
    }

    return null;
  }

  private collectMethodsWithoutValidation(resources: CloudFormationResource[]): Map<string, string[]> {
    const methodsByApi = new Map<string, string[]>();

    for (const resource of resources) {
      if (resource.Type === 'AWS::ApiGateway::Method') {
        const httpMethod = resource.Properties?.HttpMethod;
        if (httpMethod === 'OPTIONS') {
          continue;
        }

        const restApiId = this.resolveReference(resource.Properties?.RestApiId);
        if (!restApiId) {
          continue;
        }

        const requestValidatorId = resource.Properties?.RequestValidatorId;
        const requestModels = resource.Properties?.RequestModels;
        const hasValidation = !!requestValidatorId || (requestModels && Object.keys(requestModels).length > 0);

        if (!hasValidation) {
          const existing = methodsByApi.get(restApiId) || [];
          existing.push(resource.LogicalId);
          methodsByApi.set(restApiId, existing);
        }
      }
    }

    return methodsByApi;
  }

  private evaluateRestApi(
    resource: CloudFormationResource,
    stackName: string,
    methodsWithoutValidation: Map<string, string[]>
  ): ScanResult | null {
    const apiId = resource.LogicalId;
    const unvalidatedMethods = methodsWithoutValidation.get(apiId);

    if (unvalidatedMethods && unvalidatedMethods.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `API Gateway has ${unvalidatedMethods.length} method(s) without request validation`,
        `Create a RequestValidator resource AFTER the RestApi definition (it references the API, so the API must exist first). Then update EACH Method resource to include a reference to the validator.`
      );
    }

    return null;
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
}

export default new ApiGw002Rule();
