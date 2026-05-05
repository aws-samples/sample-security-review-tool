import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDms003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DMS-003',
      'HIGH',
      'DMS replication instance does not have auto minor version upgrade enabled',
      ['aws_dms_replication_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const autoMinorVersionUpgrade = resource.values?.auto_minor_version_upgrade;

    if (autoMinorVersionUpgrade === undefined || autoMinorVersionUpgrade === null) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add auto_minor_version_upgrade = true to enable automatic minor version upgrades during maintenance windows.`
      );
    }

    if (autoMinorVersionUpgrade === false) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set auto_minor_version_upgrade to true to enable automatic minor version upgrades for security patches.`
      );
    }

    return null;
  }
}

export default new TfDms003Rule();
