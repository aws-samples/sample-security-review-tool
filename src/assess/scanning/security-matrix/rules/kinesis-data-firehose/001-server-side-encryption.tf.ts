import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfKdf001Rule extends BaseTerraformRule {
  constructor() {
    super('KDF-001', 'HIGH', 'Kinesis Data Firehose delivery stream does not have server-side encryption enabled', ['aws_kinesis_firehose_delivery_stream']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_kinesis_firehose_delivery_stream') {
      const serverSideEncryption = resource.values?.server_side_encryption;

      if (!serverSideEncryption || serverSideEncryption.enabled !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Add server_side_encryption { enabled = true, key_type = "AWS_OWNED_CMK" } or use "CUSTOMER_MANAGED_CMK" with key_arn.');
      }
    }

    return null;
  }
}

export default new TfKdf001Rule();
