import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfKdf002Rule extends BaseTerraformRule {
  constructor() {
    super('KDF-002', 'HIGH', 'Kinesis Data Firehose delivery stream destination does not have encryption enabled', ['aws_kinesis_firehose_delivery_stream']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_kinesis_firehose_delivery_stream') {
      const s3Config = resource.values?.s3_configuration || resource.values?.extended_s3_configuration;

      if (s3Config) {
        if (!s3Config.kms_key_arn) {
          return this.createScanResult(resource, projectName, this.description, 'Set kms_key_arn in the S3 destination configuration to enable encryption at the destination.');
        }
      }
    }

    return null;
  }
}

export default new TfKdf002Rule();
