import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Sec006Rule extends BaseRule {
  constructor() {
    super(
      'SEC-006',
      'LOW',
      'Secret uses AWS managed KMS key instead of customer managed key',
      ['AWS::SecretsManager::Secret']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::SecretsManager::Secret') {
      // Check if KMS encryption is configured
      const kmsKeyId = resource.Properties?.KmsKeyId;

      if (kmsKeyId) {
        // Check if the KMS key is an AWS-managed key
        // AWS-managed keys typically start with 'aws/' or are ARNs containing 'aws/'
        if (typeof kmsKeyId === 'string' && kmsKeyId.includes('aws/')) {
          return this.createScanResult(
            resource,
            stackName,
            "Secret uses AWS managed KMS key instead of customer managed key",
            `Replace the AWS managed key with a customer managed KMS key for better control over the encryption key lifecycle and permissions.`
          );
        }
      }
    }

    return null;
  }
}

export default new Sec006Rule();
