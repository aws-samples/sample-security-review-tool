import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT018Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-018', 'HIGH', 'IoT resources lack proper logging configuration', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasLogging = allResources.some(r =>
        r.type === 'aws_iot_logging_options'
      );

      if (!hasLogging) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_iot_logging_options resource to configure IoT Core logging with appropriate log level.');
      }
    }

    return null;
  }
}

export default new TfIoT018Rule();
