import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfQs002Rule extends BaseTerraformRule {
  constructor() {
    super('QS-002', 'HIGH', 'QuickSight data set does not have encryption in transit enabled for SPICE', ['aws_quicksight_data_set']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_quicksight_data_set') {
      const importMode = resource.values?.import_mode;
      if (importMode !== 'SPICE') {
        return null;
      }

      const physicalTableMap = resource.values?.physical_table_map;
      if (!physicalTableMap) {
        return this.createScanResult(resource, projectName, this.description, 'Add physical_table_map with secure data source configuration for SPICE encryption in transit.');
      }
    }

    return null;
  }
}

export default new TfQs002Rule();
