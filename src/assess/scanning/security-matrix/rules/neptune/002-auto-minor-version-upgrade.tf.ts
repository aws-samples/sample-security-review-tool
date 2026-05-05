import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNeptune002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'NEPTUNE-002',
      'HIGH',
      'Neptune DB instance does not have auto minor version upgrades enabled',
      ['aws_neptune_cluster_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const autoMinorVersionUpgrade = resource.values?.auto_minor_version_upgrade;

    if (autoMinorVersionUpgrade === false) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set auto_minor_version_upgrade to true to ensure security patches and bug fixes are automatically applied.`
      );
    }

    if (autoMinorVersionUpgrade === undefined) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add auto_minor_version_upgrade = true to ensure security patches and bug fixes are automatically applied.`
      );
    }

    return null;
  }
}

export default new TfNeptune002Rule();
