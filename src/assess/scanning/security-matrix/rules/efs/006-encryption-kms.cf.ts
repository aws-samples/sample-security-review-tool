import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * EFS6 Rule: Ensure the EFS file system is configured to encrypt the data at rest using a customer managed KMS key.
 * 
 * Documentation: "Customer managed keys are the most flexible KMS keys to use with EFS because key policies and grants can
 * be configured for multiple users or services."
 * 
 * Note: Basic encryption check is covered by Checkov rule:
 * - CKV_AWS_42: Ensure EFS is encrypted at rest
 */
export class EFS006Rule extends BaseRule {
  constructor() {
    super(
      'EFS-006',
      'HIGH',
      'EFS file system is not encrypted with a customer-managed KMS key',
      ['AWS::EFS::FileSystem']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::EFS::FileSystem') {
      // Skip if Properties is missing
      if (!resource.Properties) {
        return null;
      }

      const resolver = new CloudFormationResolver(allResources);

      // Resolve the encrypted property
      const resolvedEncrypted = resolver.resolve(resource.Properties.Encrypted);

      // Skip the basic check for encryption as it's covered by Checkov
      if (!resolvedEncrypted.isResolved || !resolvedEncrypted.value) {
        return null;
      }

      const kmsKeyId = resource.Properties.KmsKeyId;

      // Check if a KMS key ID is specified
      if (!kmsKeyId) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify a customer-managed KMS key using the KmsKeyId property instead of using the default AWS managed key.`
        );
      }

      // Resolve the KMS key ID
      const resolvedKmsKey = resolver.resolve(kmsKeyId);

      // Check if the KMS key is an AWS managed key
      if (this.isAwsManagedKey(resolvedKmsKey.value)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use a customer-managed KMS key instead of the AWS managed key.`
        );
      }
    }

    return null;
  }

  /**
   * Checks if a KMS key ID refers to an AWS managed key
   * @param kmsKeyId The KMS key ID to check
   * @returns True if the key is an AWS managed key, false otherwise
   */
  private isAwsManagedKey(kmsKeyId: any): boolean {
    // If the value is null or undefined, we can't determine if it's an AWS managed key
    if (kmsKeyId === null || kmsKeyId === undefined) {
      return false;
    }

    // Direct string check
    if (typeof kmsKeyId === 'string') {
      // Check for AWS managed key patterns
      return (
        kmsKeyId.includes('alias/aws/') ||
        (kmsKeyId.includes('arn:aws:kms') && kmsKeyId.includes(':alias/aws/')) ||
        kmsKeyId.startsWith('aws/') ||
        kmsKeyId === 'AWS_OWNED_KMS_KEY'
      );
    }

    // For complex objects, we'll use the resolver to try to extract a string value
    if (typeof kmsKeyId === 'object') {
      const resolver = new CloudFormationResolver();
      const resolved = resolver.resolve(kmsKeyId);

      // If we can resolve it to a string, check that string
      if (resolved.isResolved && typeof resolved.value === 'string') {
        return this.isAwsManagedKey(resolved.value);
      }

      // If we can't resolve it but have referenced resources, check if any look like AWS managed keys
      if (!resolved.isResolved && resolved.referencedResources.length > 0) {
        return resolved.referencedResources.some(ref =>
          ref.includes('AWS') || ref.includes('aws') ||
          ref.includes('Aws') || ref.includes('KMS')
        );
      }
    }

    return false;
  }
}

export default new EFS006Rule();
