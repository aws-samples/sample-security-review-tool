import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDms001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DMS-001',
      'HIGH',
      'DMS replication instance is not configured with multi-AZ deployment',
      ['aws_dms_replication_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const multiAz = resource.values?.multi_az;

    if (multiAz === undefined || multiAz === null) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add multi_az = true to enable multi-AZ deployment for high availability and failover support.`
      );
    }

    if (multiAz === false) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set multi_az to true to enable multi-AZ deployment for high availability and failover support.`
      );
    }

    return null;
  }
}

export default new TfDms001Rule();
