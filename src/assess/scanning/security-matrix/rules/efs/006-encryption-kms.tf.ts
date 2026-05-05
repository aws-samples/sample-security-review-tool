import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEfs006Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EFS-006',
      'HIGH',
      'EFS file system is not encrypted with a customer-managed KMS key',
      ['aws_efs_file_system']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const encrypted = resource.values?.encrypted;

    if (!encrypted) {
      return null;
    }

    const kmsKeyId = resource.values?.kms_key_id;

    if (!kmsKeyId) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify a customer-managed KMS key using the kms_key_id attribute instead of using the default AWS managed key.`
      );
    }

    if (typeof kmsKeyId === 'string' && this.isAwsManagedKey(kmsKeyId)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Use a customer-managed KMS key instead of the AWS managed key.`
      );
    }

    return null;
  }

  private isAwsManagedKey(kmsKeyId: string): boolean {
    return kmsKeyId.includes('alias/aws/') ||
      (kmsKeyId.includes('arn:aws:kms') && kmsKeyId.includes(':alias/aws/')) ||
      kmsKeyId.startsWith('aws/') ||
      kmsKeyId === 'AWS_OWNED_KMS_KEY';
  }
}

export default new TfEfs006Rule();
