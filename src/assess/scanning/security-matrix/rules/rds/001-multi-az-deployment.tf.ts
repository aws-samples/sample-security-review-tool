import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-001',
      'HIGH',
      'RDS database not configured for multi-AZ deployment',
      ['aws_rds_cluster', 'aws_db_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_rds_cluster') {
      const availabilityZones = resource.values?.availability_zones;
      if (!availabilityZones || !Array.isArray(availabilityZones) || availabilityZones.length < 2) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Specify at least two availability_zones for RDS clusters to ensure high availability and fault tolerance.'
        );
      }

      if (resource.values?.engine_mode === 'serverless') {
        return null;
      }
    }

    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      if (resource.values?.multi_az !== true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set multi_az = true for RDS instances to ensure high availability and fault tolerance.'
        );
      }
    }

    return null;
  }
}

export default new TfRds001Rule();
