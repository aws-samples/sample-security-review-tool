import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Sec003Rule extends BaseRule {
  constructor() {
    super(
      'SEC-003',
      'HIGH',
      'Secret does not use customer-managed KMS encryption',
      ['AWS::SecretsManager::Secret']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::SecretsManager::Secret') {
      // Check if KMS encryption is configured
      const kmsKeyId = resource.Properties?.KmsKeyId;

      if (!kmsKeyId) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret does not use KMS encryption',
          `Add a KmsKeyId property to the secret to enable encryption with a KMS key.`
        );
      }

      // Check if the KMS key is a customer-managed key
      // AWS-managed keys typically start with 'aws/' or are ARNs containing 'aws/'
      if (typeof kmsKeyId === 'string' && kmsKeyId.includes('aws/')) {
        // This is a less severe issue - AWS-managed keys still provide strong encryption
        // But customer-managed keys offer more control and are generally preferred for sensitive data
        return this.createScanResult(
          resource,
          stackName,
          'Secret uses an AWS-managed KMS key instead of a customer-managed key',
          `Consider using a customer-managed KMS key for more control over the encryption key lifecycle.`
        );
      }
    }

    return null;
  }
}

export default new Sec003Rule();
