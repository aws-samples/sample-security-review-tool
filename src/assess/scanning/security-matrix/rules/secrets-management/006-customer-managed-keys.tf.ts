import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSec006Rule extends BaseTerraformRule {
  constructor() {
    super('SEC-006', 'LOW', 'Secret uses AWS managed KMS key instead of customer managed key', ['aws_secretsmanager_secret']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_secretsmanager_secret') {
      const kmsKeyId = resource.values?.kms_key_id;
      if (kmsKeyId && typeof kmsKeyId === 'string' && kmsKeyId.includes('aws/')) {
        return this.createScanResult(resource, projectName, this.description, 'Replace the AWS managed key with a customer managed KMS key for better control.');
      }
    }

    return null;
  }
}

export default new TfSec006Rule();
