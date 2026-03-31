import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG9 Rule: Use private API endpoints unless Internet exposure is warranted
 * 
 * Documentation: "APIs created with API Gateway are only accessible via private API endpoints 
 * and are not visible to the Internet unless it is absolutely necessary."
 */
export class ApiGw009Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-009',
      'MEDIUM',
      'API Gateway is publicly accessible without justification',
      ['AWS::ApiGateway::RestApi']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ApiGateway::RestApi') {
      // Check if this is a private API
      const endpointConfiguration = resource.Properties?.EndpointConfiguration;

      if (!endpointConfiguration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no endpoint configuration specified, defaults to public)`,
          `Add EndpointConfiguration with Types set to ['PRIVATE'] unless Internet exposure is required.`
        );
      }

      const types = endpointConfiguration.Types;

      // Check if types is an array and includes 'PRIVATE'
      const isPrivate = Array.isArray(types) && types.includes('PRIVATE');

      if (!isPrivate) {
        // Check for tags that might indicate this API is intentionally public
        const tags = this.extractTags(resource);
        const isIntentionallyPublic = this.isIntentionallyPublic(tags);

        if (!isIntentionallyPublic) {
          // Format the types for the error message
          let typesDisplay = 'not specified';
          if (types) {
            typesDisplay = Array.isArray(types) ? types.join(', ') : String(types);
          }

          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (endpoint type is ${typesDisplay})`,
            `Change EndpointConfiguration.Types to ['PRIVATE'] unless Internet exposure is required. If public access is necessary, add a tag with key 'PublicAccess' and value 'Required' with justification.`
          );
        }
      }
    }

    return null;
  }

  private extractTags(resource: CloudFormationResource): Map<string, string> {
    const tags = new Map<string, string>();
    const resourceTags = resource.Properties?.Tags;

    if (resourceTags && Array.isArray(resourceTags)) {
      for (const tag of resourceTags) {
        if (tag.Key && tag.Value) {
          tags.set(tag.Key, tag.Value);
        }
      }
    }

    return tags;
  }

  private isIntentionallyPublic(tags: Map<string, string>): boolean {
    // Check for tags that indicate this API is intentionally public
    if (tags.has('PublicAccess') && tags.get('PublicAccess') === 'Required') {
      return true;
    }

    if (tags.has('PublicAPI') && tags.get('PublicAPI') === 'True') {
      return true;
    }

    if (tags.has('InternetFacing') && tags.get('InternetFacing') === 'True') {
      return true;
    }

    // Check for a justification tag
    if (tags.has('PublicAccessJustification') && tags.get('PublicAccessJustification')?.trim()) {
      return true;
    }

    return false;
  }
}

export default new ApiGw009Rule();
