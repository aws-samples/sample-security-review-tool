import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * SSM-001 Rule: Use the least possible number of input parameters.
 * 
 * Documentation: "Reducing complexity saves testing time and increases readability."
 */
export class SSM001Rule extends BaseRule {
  constructor() {
    super(
      'SSM-001',
      'HIGH',
      'SSM Document has excessive number of input parameters',
      ['AWS::SSM::Document']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::SSM::Document') {
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
    const parameterCount = Object.keys(parameters).length;

    // Flag documents with more than 10 parameters as excessive
    if (parameterCount > 10) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (${parameterCount} parameters)`,
        `Reduce parameter count to 10 or fewer by consolidating related parameters.`
      );
    }

    return null;
  }
}

export default new SSM001Rule();