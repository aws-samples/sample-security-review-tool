import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-004',
      'HIGH',
      'Redshift cluster is publicly accessible',
      ['aws_redshift_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const publiclyAccessible = resource.values?.publicly_accessible;

    if (publiclyAccessible === true) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set publicly_accessible to false to prevent public internet access to the cluster.`
      );
    }

    if (publiclyAccessible === undefined || publiclyAccessible === null) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Explicitly set publicly_accessible to false to ensure the cluster is not publicly accessible.`
      );
    }

    return null;
  }
}

export default new TfRedshift004Rule();
