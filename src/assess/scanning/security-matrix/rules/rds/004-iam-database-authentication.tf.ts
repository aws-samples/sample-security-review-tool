import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-004',
      'HIGH',
      'RDS database does not have IAM authentication enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      const engine = resource.values?.engine;
      if (typeof engine === 'string' && this.supportsIamAuth(engine)) {
        if (resource.values?.iam_database_authentication_enabled !== true) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Set iam_database_authentication_enabled = true to enable IAM authentication for database access.'
          );
        }
      }
    }

    if (resource.type === 'aws_rds_cluster') {
      const engine = resource.values?.engine;
      if (typeof engine === 'string' && this.supportsIamAuth(engine)) {
        if (resource.values?.iam_database_authentication_enabled !== true) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Set iam_database_authentication_enabled = true to enable IAM authentication for database access at the cluster level.'
          );
        }
      }
    }

    return null;
  }

  private supportsIamAuth(engine: string): boolean {
    const lower = engine.toLowerCase();
    return lower.includes('mysql') || lower.includes('postgres');
  }
}

export default new TfRds004Rule();
