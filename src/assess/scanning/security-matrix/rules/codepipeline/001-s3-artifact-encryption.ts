import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CP1 Rule: Implement secure storage strategy in Amazon S3 for AWS CodePipeline artifacts
 * 
 * CodePipeline S3 keys can be managed by customers or AWS.
 */
export class CodePipeline001Rule extends BaseRule {
  constructor() {
    super(
      'CODEPIPELINE-001',
      'HIGH',
      'CodePipeline does not use customer-managed KMS key for S3 artifacts',
      ['AWS::CodePipeline::Pipeline']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const artifactStore = resource.Properties?.ArtifactStore;
    const artifactStores = resource.Properties?.ArtifactStores;

    // Check single artifact store
    if (artifactStore) {
      const hasSecureEncryption = this.hasSecureEncryption(artifactStore);
      if (!hasSecureEncryption) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          'Add customer-managed KMS key to ArtifactStore: "EncryptionKey": {"Type": "KMS", "Id": "arn:aws:kms:region:account:key/key-id"} or {"Type": "KMS", "Id": {"Ref": "YourKMSKeyLogicalId"}}'
        );
      }
    }

    // Check multiple artifact stores
    if (artifactStores && typeof artifactStores === 'object') {
      for (const [region, store] of Object.entries(artifactStores)) {
        const hasSecureEncryption = this.hasSecureEncryption(store);
        if (!hasSecureEncryption) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Add customer-managed KMS key to ArtifactStores.${region}: "EncryptionKey": {"Type": "KMS", "Id": "arn:aws:kms:${region}:account:key/key-id"}`
          );
        }
      }
    }

    return null;
  }

  private hasSecureEncryption(artifactStore: any): boolean {
    const encryptionKey = artifactStore?.EncryptionKey;
    if (!encryptionKey) {
      return false;
    }

    // Must be KMS type
    if (encryptionKey.Type !== 'KMS') {
      return false;
    }

    // Check if using AWS managed key
    const keyId = encryptionKey.Id;
    if (typeof keyId === 'string' && (keyId.includes('alias/aws/') || keyId.startsWith('aws/'))) {
      return false;
    }

    return true;
  }
}

export default new CodePipeline001Rule();