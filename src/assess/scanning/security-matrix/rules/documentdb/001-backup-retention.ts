import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class DocumentDB001Rule extends BaseRule {
  constructor() {
    super(
      'DOCDB-001',
      'HIGH',
      'DocumentDB cluster does not have a minimum backup retention period configured',
      ['AWS::DocDB::DBCluster']
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
        `Configure BackupRetentionPeriod to a value between 1 and 35 days.`
      );
    }

    if (resource.Type === 'AWS::DocDB::DBCluster') {
      return this.evaluateCluster(resource, stackName);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const backupRetentionPeriod = resource.Properties.BackupRetentionPeriod;

    // If BackupRetentionPeriod is not specified, DocumentDB defaults to 1 day
    // Since the requirement is that "even a single day of retention is fine",
    // we'll allow undefined values (defaults to 1 day)
    if (backupRetentionPeriod === undefined || backupRetentionPeriod === null) {
      // AWS default is 1 day, which meets our minimum requirement
      return null;
    }

    // Handle CloudFormation intrinsic functions
    if (typeof backupRetentionPeriod === 'object') {
      // Could be a Ref, GetAtt, or other intrinsic function
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set BackupRetentionPeriod to an explicit numeric value between 1 and 35 days rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Convert to number for validation
    const retentionDays = Number(backupRetentionPeriod);

    // Check if it's a valid number
    if (isNaN(retentionDays)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set BackupRetentionPeriod to a valid numeric value between 1 and 35 days (current value: ${backupRetentionPeriod}).`
      );
    }

    // Check if backup retention is disabled (0)
    if (retentionDays === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable automated backups by setting BackupRetentionPeriod to a value between 1 and 35 days (current value: disabled).`
      );
    }

    // Check if retention period is within valid range (1-35 days)
    if (retentionDays < 1 || retentionDays > 35) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set BackupRetentionPeriod to a value between 1 and 35 days (current value: ${retentionDays} days).`
      );
    }

    // Compliant: retention period is set and within valid range (>=1 day)
    return null;
  }
}

export default new DocumentDB001Rule();