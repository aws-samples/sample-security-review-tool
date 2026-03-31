import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift005Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-005',
      'HIGH',
      'Redshift cluster does not have automated snapshot retention configured',
      ['AWS::Redshift::Cluster']
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
        `Configure AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days.`
      );
    }

    if (resource.Type === 'AWS::Redshift::Cluster') {
      return this.evaluateCluster(resource, stackName);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const retentionPeriod = resource.Properties.AutomatedSnapshotRetentionPeriod;

    // If AutomatedSnapshotRetentionPeriod is not specified, it defaults to 1 day
    // However, for security compliance, we want it to be explicitly configured
    if (retentionPeriod === undefined || retentionPeriod === null) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Explicitly set AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days (recommended: 7 days or more for production workloads).`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof retentionPeriod === 'object') {
      // Could be a Ref, GetAtt, or other intrinsic function
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutomatedSnapshotRetentionPeriod to an explicit numeric value between 1 and 35 days rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Convert to number for validation
    const retentionDays = Number(retentionPeriod);

    // Check if it's a valid number
    if (isNaN(retentionDays)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutomatedSnapshotRetentionPeriod to a valid numeric value between 1 and 35 days (current value: ${retentionPeriod}).`
      );
    }

    // Check if retention period is disabled (0)
    if (retentionDays === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable automated snapshots by setting AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days (current value: disabled).`
      );
    }

    // Check if retention period is within valid range (1-35 days)
    if (retentionDays < 1 || retentionDays > 35) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutomatedSnapshotRetentionPeriod to a value between 1 and 35 days (current value: ${retentionDays} days).`
      );
    }

    // Compliant: retention period is set and within reasonable range
    return null;
  }
}

export default new Redshift005Rule();