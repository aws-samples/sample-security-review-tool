import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSec003Rule extends BaseTerraformRule {
  constructor() {
    super('SEC-003', 'HIGH', 'Secret does not use customer-managed KMS encryption', ['aws_secretsmanager_secret']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_secretsmanager_secret') {
      const kmsKeyId = resource.values?.kms_key_id;
      if (!kmsKeyId) {
        return this.createScanResult(resource, projectName, 'Secret does not use KMS encryption', 'Set kms_key_id to a customer-managed KMS key ARN.');
      }

      if (typeof kmsKeyId === 'string' && kmsKeyId.includes('aws/')) {
        return this.createScanResult(resource, projectName, 'Secret uses an AWS-managed KMS key instead of a customer-managed key', 'Use a customer-managed KMS key for more control over the encryption key lifecycle.');
      }
    }

    return null;
  }
}

export default new TfSec003Rule();
