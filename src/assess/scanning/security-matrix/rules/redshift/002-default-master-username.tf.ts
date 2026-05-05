import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-002',
      'HIGH',
      'Redshift cluster is using the default master username "awsuser"',
      ['aws_redshift_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const masterUsername = resource.values?.master_username;

    if (!masterUsername) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify a custom master_username other than "awsuser".`
      );
    }

    if (masterUsername === 'awsuser') {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Change master_username to a value other than "awsuser".`
      );
    }

    return null;
  }
}

export default new TfRedshift002Rule();
