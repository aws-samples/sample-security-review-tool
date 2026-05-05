import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfKda003Rule extends BaseTerraformRule {
  constructor() {
    super('KDA-003', 'HIGH', 'Kinesis Data Analytics V2 application does not have checkpoints configured for backup and recovery', ['aws_kinesisanalyticsv2_application']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_kinesisanalyticsv2_application') {
      const appConfig = resource.values?.application_configuration;
      if (!appConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add application_configuration with flink_application_configuration.checkpoint_configuration.');
      }

      const flinkConfig = appConfig.flink_application_configuration;
      if (flinkConfig) {
        const checkpointConfig = flinkConfig.checkpoint_configuration;
        if (checkpointConfig?.configuration_type === 'CUSTOM' && checkpointConfig?.checkpointing_enabled === false) {
          return this.createScanResult(resource, projectName, this.description, 'Set checkpoint_configuration.checkpointing_enabled = true.');
        }
      }
    }

    return null;
  }
}

export default new TfKda003Rule();
