import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT019Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-019', 'HIGH', 'IoT deployment lacks CloudWatch monitoring and alarms', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasCloudWatchAlarm = allResources.some(r =>
        r.type === 'aws_cloudwatch_metric_alarm' &&
        (r.values?.namespace === 'AWS/IoT' || JSON.stringify(r.values).includes('IoT'))
      );

      if (!hasCloudWatchAlarm) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_cloudwatch_metric_alarm resources with namespace "AWS/IoT" to monitor IoT metrics.');
      }
    }

    return null;
  }
}

export default new TfIoT019Rule();
