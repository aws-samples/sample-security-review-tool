import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfVpc003Rule extends BaseTerraformRule {
  constructor() {
    super('VPC-003', 'HIGH', 'Flow log destination does not have a retention period configured', ['aws_flow_log']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_flow_log') {
      const logDestinationType = resource.values?.log_destination_type || 'cloud-watch-logs';

      if (logDestinationType === 'cloud-watch-logs') {
        const logGroupArn = resource.values?.log_destination || resource.values?.log_group_name;
        const logGroups = allResources.filter(r => r.type === 'aws_cloudwatch_log_group');
        const matchingLogGroup = logGroups.find(lg =>
          lg.values?.arn === logGroupArn || lg.values?.name === logGroupArn
        );

        if (matchingLogGroup && !matchingLogGroup.values?.retention_in_days) {
          return this.createScanResult(resource, projectName, this.description, 'Set retention_in_days on the associated aws_cloudwatch_log_group resource.');
        }
      }

      if (logDestinationType === 's3') {
        const logDestination = resource.values?.log_destination;
        const buckets = allResources.filter(r => r.type === 'aws_s3_bucket');
        const matchingBucket = buckets.find(b =>
          logDestination && logDestination.includes(b.values?.bucket)
        );

        if (matchingBucket) {
          const hasLifecycle = allResources.some(r =>
            r.type === 'aws_s3_bucket_lifecycle_configuration' &&
            r.values?.bucket === matchingBucket.values?.bucket
          );

          if (!hasLifecycle) {
            return this.createScanResult(resource, projectName, this.description, 'Add aws_s3_bucket_lifecycle_configuration with expiration rules for the S3 bucket receiving flow logs.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfVpc003Rule();
