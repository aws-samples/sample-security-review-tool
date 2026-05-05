import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT028Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-028', 'MEDIUM', 'IoT deployment lacks backup and recovery planning', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasS3Action = resource.values?.s3 || resource.values?.dynamodb || resource.values?.dynamodbv2;
      if (!hasS3Action) {
        const hasBackupDestination = allResources.some(r =>
          r.type === 'aws_iot_topic_rule' &&
          (r.values?.s3 || r.values?.dynamodb || r.values?.dynamodbv2 || r.values?.kinesis)
        );

        if (!hasBackupDestination) {
          return this.createScanResult(resource, projectName, this.description, 'Configure IoT topic rules to persist data to S3, DynamoDB, or Kinesis for backup and recovery.');
        }
      }
    }

    return null;
  }
}

export default new TfIoT028Rule();
