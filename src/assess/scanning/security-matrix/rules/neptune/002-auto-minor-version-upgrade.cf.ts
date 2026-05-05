import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Neptune002Rule extends BaseRule {
  constructor() {
    super(
      'NEPTUNE-002',
      'HIGH',
      'Neptune DB instance does not have auto minor version upgrades enabled',
      ['AWS::Neptune::DBInstance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Check if AutoMinorVersionUpgrade property exists and is set to true
    const autoMinorVersionUpgrade = resource.Properties?.AutoMinorVersionUpgrade;

    // If the property is explicitly set to false, return a scan result
    if (autoMinorVersionUpgrade === false) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set AutoMinorVersionUpgrade to true to ensure security patches and bug fixes are automatically applied.`
      );
    }

    // If the property is missing (undefined), return a scan result
    if (autoMinorVersionUpgrade === undefined) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add AutoMinorVersionUpgrade: true to ensure security patches and bug fixes are automatically applied.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof autoMinorVersionUpgrade === 'object') {
      // We can't determine the actual value at scan time, so we'll assume it's compliant
      // This is a limitation of static analysis of CloudFormation templates
      return null;
    }

    // If autoMinorVersionUpgrade is true, the resource is compliant
    return null;
  }
}

export default new Neptune002Rule();
