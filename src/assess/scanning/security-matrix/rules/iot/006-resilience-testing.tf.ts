import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT006Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-006', 'MEDIUM', 'IoT deployment lacks resilience testing and disaster recovery planning', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasErrorAction = resource.values?.error_action;
      if (!hasErrorAction) {
        return this.createScanResult(resource, projectName, this.description, 'Add error_action to topic rules for resilience handling when primary actions fail.');
      }
    }

    return null;
  }
}

export default new TfIoT006Rule();
