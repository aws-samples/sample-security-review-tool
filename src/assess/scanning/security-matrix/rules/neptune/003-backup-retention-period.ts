import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Neptune003Rule extends BaseRule {
  constructor() {
    super(
      'NEPTUNE-003',
      'HIGH',
      'Neptune cluster does not have a minimum backup retention period of 7 days configured',
      ['AWS::Neptune::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Check if BackupRetentionPeriod property exists and is set to at least 7 days
    const backupRetentionPeriod = resource.Properties?.BackupRetentionPeriod;

    // If the property is missing (undefined), return a scan result
    if (backupRetentionPeriod === undefined) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set BackupRetentionPeriod to at least 7 days to ensure adequate data recovery capabilities.`
      );
    }

    // If the property is explicitly set to a value less than 7, return a scan result
    if (typeof backupRetentionPeriod === 'number' && backupRetentionPeriod < 7) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Increase BackupRetentionPeriod to at least 7 days (currently set to ${backupRetentionPeriod}).`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof backupRetentionPeriod === 'object') {
      // We can't determine the actual value at scan time, so we'll assume it's compliant
      // This is a limitation of static analysis of CloudFormation templates
      return null;
    }

    // If backupRetentionPeriod is 7 or greater, the resource is compliant
    return null;
  }
}

export default new Neptune003Rule();
