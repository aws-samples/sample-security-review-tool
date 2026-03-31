import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class DMS001Rule extends BaseRule {
  constructor() {
    super(
      'DMS-001',
      'HIGH',
      'DMS replication instance is not configured with multi-AZ deployment',
      ['AWS::DMS::ReplicationInstance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure MultiAZ property to true to enable multi-AZ deployment for high availability.`
      );
    }

    if (resource.Type === 'AWS::DMS::ReplicationInstance') {
      return this.evaluateReplicationInstance(resource, stackName);
    }

    return null;
  }

  private evaluateReplicationInstance(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const multiAZ = resource.Properties.MultiAZ;

    // If MultiAZ is not specified, it defaults to false (single-AZ)
    if (multiAZ === undefined || multiAZ === null) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add MultiAZ property and set it to true to enable multi-AZ deployment for high availability and failover support.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof multiAZ === 'object') {
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set MultiAZ property to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Check if MultiAZ is explicitly disabled
    if (multiAZ === false || multiAZ === 'false') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set MultiAZ property to true to enable multi-AZ deployment for high availability and failover support.`
      );
    }

    // Check if MultiAZ is enabled
    if (multiAZ === true || multiAZ === 'true') {
      return null; // Compliant
    }

    // For any other unexpected value, flag as non-compliant
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Set MultiAZ property to true (current value: ${multiAZ}).`
    );
  }
}

export default new DMS001Rule();