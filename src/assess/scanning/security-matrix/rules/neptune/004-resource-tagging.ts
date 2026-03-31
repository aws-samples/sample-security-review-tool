import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Neptune004Rule extends BaseRule {
  constructor() {
    super(
      'NEPTUNE-004',
      'MEDIUM', // Using MEDIUM priority as tagging is important but not as critical as availability or security patches
      'Neptune cluster is missing required tags',
      ['AWS::Neptune::DBCluster'] // Only apply to cluster resources
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Check if Tags property exists and has at least one tag
    const tags = resource.Properties?.Tags;

    // If tags are missing or empty, return a scan result
    if (!tags || !Array.isArray(tags) || tags.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add appropriate tags to Neptune clusters for better resource management, cost allocation, and security tracking.`
      );
    }

    // If we have tags, the resource is compliant
    return null;
  }
}

export default new Neptune004Rule();
