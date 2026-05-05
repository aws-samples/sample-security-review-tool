import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * SSM-002 Rule: Validate AWS SSM automation document parameters with allowedPattern and allowedValue conditions.
 * 
 * Documentation: "Use an allow-list approach with parameters to deny non-compliant parameters by default."
 */
export class SSM002Rule extends BaseRule {
  constructor() {
    super(
      'SSM-002',
      'HIGH',
      'SSM Automation Document parameter lacks validation constraints',
      ['AWS::SSM::Document']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::SSM::Document') {
      return null;
    }

    const documentType = resource.Properties?.DocumentType;
    if (documentType !== 'Automation') {
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

    const parameters = content.parameters || {};
    
    for (const [paramName, paramConfig] of Object.entries(parameters)) {
      if (typeof paramConfig === 'object' && paramConfig !== null) {
        const config = paramConfig as any;
        const hasAllowedPattern = config.allowedPattern;
        const hasAllowedValues = config.allowedValues;
        const hasDefault = config.default !== undefined;
        const paramType = config.type;

        // Skip validation for certain types that don't need constraints
        if (paramType === 'Boolean' || hasDefault) {
          continue;
        }

        if (!hasAllowedPattern && !hasAllowedValues) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (parameter: ${paramName})`,
            `Add allowedPattern or allowedValues constraint to parameter '${paramName}' for input validation.`
          );
        }
      }
    }

    return null;
  }
}

export default new SSM002Rule();