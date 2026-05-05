import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk006Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-006', 'HIGH', 'MSK cluster does not have broker log delivery configured', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const loggingInfo = resource.values?.logging_info;
      const brokerLogs = loggingInfo?.broker_logs || loggingInfo?.[0]?.broker_logs?.[0];

      if (!brokerLogs) {
        return this.createScanResult(resource, projectName, this.description, 'Add logging_info.broker_logs with cloudwatch_logs { enabled = true, log_group = "/aws/msk/broker-logs" }.');
      }

      const cwEnabled = brokerLogs.cloudwatch_logs?.enabled || brokerLogs.cloudwatch_logs?.[0]?.enabled;
      const s3Enabled = brokerLogs.s3?.enabled || brokerLogs.s3?.[0]?.enabled;
      const firehoseEnabled = brokerLogs.firehose?.enabled || brokerLogs.firehose?.[0]?.enabled;

      if (!cwEnabled && !s3Enabled && !firehoseEnabled) {
        return this.createScanResult(resource, projectName, this.description, 'Enable at least one broker log destination (cloudwatch_logs, s3, or firehose).');
      }
    }

    return null;
  }
}

export default new TfMsk006Rule();
