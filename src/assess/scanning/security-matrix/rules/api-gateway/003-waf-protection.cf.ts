import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG3 Rule: Use AWS WAF on public-facing API Gateway Endpoints
 * 
 * Documentation: "AWS WAF prevents many common web attacks. It should be used any time a large, 
 * diverse, and unregulated set of systems will be making API calls."
 * 
 * Note: Basic WAF association check is covered by Checkov rule CKV_AWS_73, which verifies that
 * an API Gateway has a WAF enabled. This rule extends that functionality by specifically checking
 * public-facing endpoints and providing more detailed remediation guidance.
 */
export class ApiGw003Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-003',
      'HIGH',
      'Public API Gateway endpoint lacks WAF protection',
      ['AWS::ApiGateway::Stage']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::ApiGateway::Stage') {
      // Check if this is a public API stage
      const restApiId = this.resolveReference(resource.Properties?.RestApiId);
      let isPublicStage = true; // Default to true (safer)
      
      if (restApiId) {
        // Find the associated API to determine if it's public
        const api = allResources.find(r => 
          r.Type === 'AWS::ApiGateway::RestApi' && 
          r.LogicalId === restApiId
        );
        
        if (api) {
          // If we found the API, check if it's public
          isPublicStage = this.isPublicApi(api);
        } else {
          // If we can't find the API, use the stage-based check
          isPublicStage = this.isPublicStage(resource);
        }
      } else {
        // If there's no RestApiId, use the stage-based check
        isPublicStage = this.isPublicStage(resource);
      }

      if (isPublicStage) {
        // Check if WAF is associated with this stage
        const hasWafProtection = this.hasWafProtection(resource, allResources);

        if (!hasWafProtection) {
          return this.createScanResult(
            resource,
            stackName,
          `${this.description}`,
          `Create an AWS::WAFv2::WebACL and associate it with this API Gateway stage using AWS::WAFv2::WebACLAssociation.`
        );
        }
      }
    }

    return null;
  }

  private hasWafProtection(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    const wafWebAcls = allResources.filter(r =>
      r.Type === 'AWS::WAFv2::WebACL' ||
      r.Type === 'AWS::WAF::WebACL' ||
      r.Type === 'AWS::WAFRegional::WebACL'
    );

    if (wafWebAcls.length === 0) {
      return false;
    }

    const stageId = resource.LogicalId;
    const restApiId = this.resolveReference(resource.Properties?.RestApiId);

    const wafAssociations = allResources.filter(r =>
      (r.Type === 'AWS::WAFv2::WebACLAssociation' ||
        r.Type === 'AWS::WAFRegional::WebACLAssociation') &&
      r.Properties?.ResourceArn
    );

    for (const association of wafAssociations) {
      const resourceArn = association.Properties.ResourceArn;

      if (typeof resourceArn === 'object' && resourceArn['Fn::GetAtt']) {
        const getAtt = resourceArn['Fn::GetAtt'];
        if (Array.isArray(getAtt) && getAtt[0] === stageId) {
          return true;
        }
      }

      if (typeof resourceArn === 'object' && resourceArn.Ref === stageId) {
        return true;
      }

      if (typeof resourceArn === 'string' && resourceArn.includes(stageId)) {
        return true;
      }

      // Handle Fn::Join (CDK pattern) - look for RestApi or Stage references
      if (typeof resourceArn === 'object' && resourceArn['Fn::Join'] && Array.isArray(resourceArn['Fn::Join'])) {
        const joinParts = resourceArn['Fn::Join'][1];
        if (Array.isArray(joinParts) && this.joinContainsApiReference(joinParts, stageId, restApiId)) {
          return true;
        }
      }

      // Handle Fn::Sub (CDK pattern)
      if (typeof resourceArn === 'object' && resourceArn['Fn::Sub']) {
        if (this.subContainsApiReference(resourceArn['Fn::Sub'], stageId, restApiId)) {
          return true;
        }
      }
    }

    return false;
  }

  private joinContainsApiReference(joinParts: any[], stageId: string, restApiId: string | null): boolean {
    for (const part of joinParts) {
      if (typeof part === 'object' && part.Ref) {
        if (part.Ref === stageId || (restApiId && part.Ref === restApiId)) {
          return true;
        }
      }
      if (typeof part === 'object' && part['Fn::GetAtt'] && Array.isArray(part['Fn::GetAtt'])) {
        const ref = part['Fn::GetAtt'][0];
        if (ref === stageId || (restApiId && ref === restApiId)) {
          return true;
        }
      }
      if (typeof part === 'string') {
        if (part.includes(stageId) || (restApiId && part.includes(restApiId))) {
          return true;
        }
      }
    }
    return false;
  }

  private subContainsApiReference(subValue: any, stageId: string, restApiId: string | null): boolean {
    if (typeof subValue === 'string') {
      return subValue.includes(stageId) || (restApiId !== null && subValue.includes(restApiId));
    }
    if (Array.isArray(subValue) && subValue.length >= 2) {
      const template = subValue[0];
      const vars = subValue[1];
      if (typeof template === 'string') {
        if (template.includes(stageId) || (restApiId && template.includes(restApiId))) {
          return true;
        }
      }
      if (typeof vars === 'object') {
        for (const value of Object.values(vars)) {
          if (typeof value === 'object' && value !== null) {
            const v = value as Record<string, any>;
            if (v.Ref === stageId || (restApiId && v.Ref === restApiId)) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  private isPublicStage(resource: CloudFormationResource): boolean {
    // First, check if this stage is associated with a private API
    const restApiId = resource.Properties?.RestApiId;
    
    // If we can't determine the API, we can't determine if it's public
    if (!restApiId) {
      // Check for stage name that suggests this is a public stage
      // Only use this as a fallback if we can't determine from API association
      const stageName = resource.Properties?.StageName || '';
      const publicKeywords = ['prod', 'production', 'public', 'external', 'api'];
      const privateKeywords = ['private', 'internal', 'vpc'];
      
      // If it has private keywords, it's likely not public
      if (privateKeywords.some(keyword => stageName.toLowerCase().includes(keyword))) {
        return false;
      }
      
      // If it has public keywords, it might be public
      if (publicKeywords.some(keyword => stageName.toLowerCase().includes(keyword))) {
        return true;
      }
      
      // Default to true for stages we can't determine - safer to assume public and require WAF
      return true;
    }
    
    // If we have allResources in the evaluate method, we'll check the API there
    // For now, default to true - safer to assume public and require WAF
    return true;
  }

  private isPublicApi(resource: CloudFormationResource): boolean {
    // Check for endpoint configuration - this is the primary indicator
    const endpointConfiguration = resource.Properties?.EndpointConfiguration;

    if (endpointConfiguration) {
      const types = this.resolveEndpointTypes(endpointConfiguration.Types);

      if (types && Array.isArray(types)) {
        // If the endpoint type is PRIVATE, it's definitely not a public API
        if (types.includes('PRIVATE')) {
          return false;
        }
        
        // If the endpoint type is EDGE or REGIONAL, it's a public API
        if (types.includes('EDGE') || types.includes('REGIONAL')) {
          return true;
        }
      }
    }

    // Check for policy document that might restrict access
    const policy = resource.Properties?.Policy;
    if (policy) {
      // If there's a policy with a VPC condition, it might be restricted to VPC access
      const policyStr = JSON.stringify(policy);
      if (policyStr.includes('aws:SourceVpc') || policyStr.includes('aws:VpcSourceIp')) {
        return false;
      }
    }

    // Check for name-based indicators
    const apiName = resource.Properties?.Name || '';
    const publicKeywords = ['public', 'external', 'api'];
    const privateKeywords = ['private', 'internal', 'vpc'];
    
    // If it has private keywords, it's likely not public
    if (privateKeywords.some(keyword => apiName.toLowerCase().includes(keyword))) {
      return false;
    }
    
    // If it has public keywords, it might be public
    if (publicKeywords.some(keyword => apiName.toLowerCase().includes(keyword))) {
      return true;
    }
    
    // Default to true - safer to assume public and require WAF
    return true;
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

export default new ApiGw003Rule();
