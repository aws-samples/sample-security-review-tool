import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class DMS003Rule extends BaseRule {
  constructor() {
    super(
      'DMS-003',
      'HIGH',
      'DMS replication instance does not have auto minor version upgrade enabled',
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
        `Configure AutoMinorVersionUpgrade property to true to enable automatic minor version upgrades.`
      );
    }

    if (resource.Type === 'AWS::DMS::ReplicationInstance') {
      return this.evaluateReplicationInstance(resource, stackName);
    }

    return null;
  }

  private evaluateReplicationInstance(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const autoMinorVersionUpgrade = resource.Properties.AutoMinorVersionUpgrade;

    // If AutoMinorVersionUpgrade is not specified, it defaults to false
    if (autoMinorVersionUpgrade === undefined || autoMinorVersionUpgrade === null) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add AutoMinorVersionUpgrade property and set it to true to enable automatic minor version upgrades during maintenance windows.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof autoMinorVersionUpgrade === 'object') {
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutoMinorVersionUpgrade property to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Check if AutoMinorVersionUpgrade is explicitly disabled
    if (autoMinorVersionUpgrade === false || autoMinorVersionUpgrade === 'false') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutoMinorVersionUpgrade property to true to enable automatic minor version upgrades for security patches and performance improvements.`
      );
    }

    // Check if AutoMinorVersionUpgrade is enabled
    if (autoMinorVersionUpgrade === true || autoMinorVersionUpgrade === 'true') {
      return null; // Compliant
    }

    // For any other unexpected value, flag as non-compliant
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Set AutoMinorVersionUpgrade property to true (current value: ${autoMinorVersionUpgrade}).`
    );
  }
}

export default new DMS003Rule();