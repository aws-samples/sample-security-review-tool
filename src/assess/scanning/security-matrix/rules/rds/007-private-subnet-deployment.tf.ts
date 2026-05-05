import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds007Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-007',
      'HIGH',
      'RDS Database deployed in public subnet',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      const dbSubnetGroupName = resource.values?.db_subnet_group_name;
      if (!dbSubnetGroupName) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Specify a db_subnet_group_name with private subnets only.'
        );
      }

      if (resource.values?.publicly_accessible === true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set publicly_accessible = false and use a subnet group with private subnets only.'
        );
      }
    }

    if (resource.type === 'aws_rds_cluster') {
      const dbSubnetGroupName = resource.values?.db_subnet_group_name;
      if (!dbSubnetGroupName) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Specify a db_subnet_group_name with private subnets only.'
        );
      }
    }

    return null;
  }
}

export default new TfRds007Rule();
