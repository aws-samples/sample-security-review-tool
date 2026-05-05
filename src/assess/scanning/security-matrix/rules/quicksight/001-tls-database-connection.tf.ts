import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfQs001Rule extends BaseTerraformRule {
  constructor() {
    super('QS-001', 'HIGH', 'QuickSight data source does not have TLS enabled for database connections', ['aws_quicksight_data_source']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_quicksight_data_source') {
      const sslProperties = resource.values?.ssl_properties;
      if (sslProperties?.disable_ssl === true) {
        return this.createScanResult(resource, projectName, this.description, 'Set ssl_properties.disable_ssl = false to enable TLS for database connections.');
      }

      const parameters = resource.values?.parameters;
      if (parameters) {
        const hasDbParams = parameters.rds || parameters.aurora || parameters.aurora_postgresql ||
          parameters.maria_db || parameters.mysql || parameters.oracle ||
          parameters.postgresql || parameters.sql_server || parameters.redshift;

        if (hasDbParams && !sslProperties) {
          return this.createScanResult(resource, projectName, this.description, 'Add ssl_properties { disable_ssl = false } to enable TLS for database connections.');
        }
      }
    }

    return null;
  }
}

export default new TfQs001Rule();
