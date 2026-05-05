import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT031Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-031', 'HIGH', 'IoT topic rule does not have CloudWatch logging action configured', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasCloudwatchAction = resource.values?.cloudwatch_logs || resource.values?.cloudwatch_metric || resource.values?.cloudwatch_alarm;

      if (!hasCloudwatchAction) {
        const hasLoggingOptions = allResources.some(r =>
          r.type === 'aws_iot_logging_options'
        );

        if (!hasLoggingOptions) {
          return this.createScanResult(resource, projectName, this.description, 'Add cloudwatch_logs action to the topic rule or configure aws_iot_logging_options for centralized logging.');
        }
      }
    }

    return null;
  }
}

export default new TfIoT031Rule();
