import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK6 Rule: Are broker logs being delivered to a supported destination?
 * 
 * Documentation: "Broker logs enable you to troubleshoot your Apache Kafka applications and to analyze their communications with your MSK cluster. 
 * You can configure your cluster to deliver logs to the following resources: a CloudWatch log group, an S3 bucket, a Kinesis Data Firehose delivery stream."
 */
export class MSK006Rule extends BaseRule {
  constructor() {
    super(
      'MSK-006',
      'HIGH',
      'MSK cluster does not have broker log delivery configured',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    // Check if LoggingInfo is configured
    const loggingInfo = resource.Properties?.LoggingInfo;
    if (!loggingInfo) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add LoggingInfo.BrokerLogs.CloudWatchLogs with Enabled: true and LogGroup: '/aws/msk/broker-logs' to enable CloudWatch Logs delivery.`
      );
    }

    // Check if BrokerLogs is configured
    const brokerLogs = loggingInfo.BrokerLogs;
    if (!brokerLogs) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add LoggingInfo.BrokerLogs.CloudWatchLogs with Enabled: true and LogGroup: '/aws/msk/broker-logs' to enable broker log delivery.`
      );
    }

    // Check if at least one supported destination is configured
    const hasCloudWatchLogs = brokerLogs.CloudWatchLogs?.Enabled === true;
    const hasS3 = brokerLogs.S3?.Enabled === true;
    const hasFirehose = brokerLogs.Firehose?.Enabled === true;

    if (!hasCloudWatchLogs && !hasS3 && !hasFirehose) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set LoggingInfo.BrokerLogs.CloudWatchLogs.Enabled to true and LogGroup to '/aws/msk/broker-logs' to enable broker log delivery.`
      );
    }

    return null;
  }
}

export default new MSK006Rule();