import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCodeDeploy001Rule extends BaseTerraformRule {
  constructor() {
    super('CODEDEPLOY-001', 'HIGH', 'CodeDeploy deployment group lacks CloudWatch alarms for monitoring', ['aws_codedeploy_deployment_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_codedeploy_deployment_group') {
      const alarmConfiguration = resource.values?.alarm_configuration;
      if (!alarmConfiguration || !alarmConfiguration.alarms || alarmConfiguration.alarms.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Add alarm_configuration with CloudWatch alarms to monitor deployment health.');
      }
    }

    return null;
  }
}

export default new TfCodeDeploy001Rule();
