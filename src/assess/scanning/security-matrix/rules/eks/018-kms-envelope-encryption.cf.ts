import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS18 Rule: Ensure that AWS KMS for envelope encryption is used for Kubernetes secrets.
 * 
 * Documentation: "With the KMS plugin for Kubernetes, all Kubernetes secrets are stored in etcd
 * in ciphertext instead of plain text and can only be decrypted by the Kubernetes API server.
 * 
 * Recomentations:
 * - Rotate your secrets periodically
 * - Use separate namespaces as a way to isolate secrets from different applications
 * - Use volume mounts instead of environment variables
 * - Use an external secrets provider (AWS Secret manager or Vault)"
 * 
 * Note: This rule is partially covered by Checkov rule CKV_AWS_164 which checks if EKS cluster has secrets encryption enabled.
 * This rule adds additional checks for KMS key configuration.
 */
export class EKS018Rule extends BaseRule {
  private eksKmsKeyRefs: Set<string> = new Set();

  constructor() {
    super(
      'EKS-018',
      'HIGH',
      'EKS cluster does not have KMS envelope encryption configured for Kubernetes secrets',
      ['AWS::EKS::Cluster', 'AWS::KMS::Key']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (allResources && !this.eksKmsKeyRefs.size) {
      this.collectEksKmsKeyRefs(allResources);
    }

    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      const encryptionConfig = resource.Properties?.EncryptionConfig;

      // Check if encryption config is missing
      if (!encryptionConfig || !Array.isArray(encryptionConfig) || encryptionConfig.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no encryption configuration)`,
          `Configure EncryptionConfig with a KMS key to encrypt Kubernetes secrets.`
        );
      }

      // Handle CloudFormation intrinsic functions for encryptionConfig
      if (typeof encryptionConfig === 'object' && !Array.isArray(encryptionConfig)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set EncryptionConfig to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      // Check if secrets encryption is configured
      const hasSecretsEncryption = encryptionConfig.some(config => {
        const resources = config.Resources;
        // Check if resources is an intrinsic function
        if (resources && typeof resources === 'object' && !Array.isArray(resources)) {
          // Can't validate at scan time, but we'll check other configs
          return false;
        }
        return resources && Array.isArray(resources) && resources.includes('secrets');
      });

      if (!hasSecretsEncryption) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (secrets not included in encryption resources)`,
          `Include 'secrets' in the Resources array of EncryptionConfig.`
        );
      }

      // Check if a proper KMS key is configured
      const hasProperKmsKey = encryptionConfig.some(config => {
        const provider = config.Provider;
        return provider && provider.KeyArn;
      });

      if (!hasProperKmsKey) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no KMS key ARN provided)`,
          `Specify a KMS key ARN in the Provider.KeyArn property.`
        );
      }

      // Check for intrinsic functions in KeyArn
      for (const config of encryptionConfig) {
        const provider = config.Provider;
        if (provider && provider.KeyArn) {
          const keyArn = provider.KeyArn;
          if (typeof keyArn === 'object') {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `While references to KMS keys are common, ensure the referenced key is properly configured with rotation enabled and appropriate permissions.`
            );
          }
        }
      }

      // Check if the referenced KMS key has proper configuration
      if (allResources) {
        const kmsKeyRefs = this.extractKmsKeyRefs(encryptionConfig);
        const hasProperKmsKeyConfig = this.hasProperKmsKeyConfig(kmsKeyRefs, allResources);

        if (!hasProperKmsKeyConfig) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (KMS key not properly configured)`,
            `Configure the KMS key with proper key policy, rotation, and description.`
          );
        }
      }
    }

    // Check if this is a KMS key that might be used for EKS secrets encryption
    if (resource.Type === 'AWS::KMS::Key') {
      const isEksRelatedKey = this.isEksRelatedKey(resource);

      if (isEksRelatedKey) {
        // Check if key rotation is enabled
        const enableKeyRotation = resource.Properties?.EnableKeyRotation;

        // Handle CloudFormation intrinsic functions for EnableKeyRotation
        if (typeof enableKeyRotation === 'object') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set EnableKeyRotation to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.`
          );
        }

        if (enableKeyRotation !== true) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (key rotation not enabled)`,
            `Enable key rotation by setting EnableKeyRotation to true.`
          );
        }

        // Check if key policy allows EKS service to use the key
        const keyPolicy = resource.Properties?.KeyPolicy;

        // Handle CloudFormation intrinsic functions for KeyPolicy
        if (keyPolicy && typeof keyPolicy === 'object' && !Array.isArray(keyPolicy) && !keyPolicy.Statement) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set KeyPolicy to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
          );
        }

        if (keyPolicy) {
          const allowsEksService = this.keyPolicyAllowsEksService(keyPolicy);

          if (!allowsEksService) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (key policy does not allow EKS service)`,
              `Update the key policy to allow the EKS service to use the key.`
            );
          }
        }
      }
    }

    return null;
  }

  private collectEksKmsKeyRefs(allResources: CloudFormationResource[]): void {
    for (const resource of allResources) {
      if (resource.Type === 'AWS::EKS::Cluster') {
        const encryptionConfig = resource.Properties?.EncryptionConfig;
        if (encryptionConfig && Array.isArray(encryptionConfig)) {
          const keyRefs = this.extractKmsKeyRefs(encryptionConfig);
          keyRefs.forEach(ref => this.eksKmsKeyRefs.add(ref));
        }
      }
    }
  }

  private extractKmsKeyRefs(encryptionConfig: any[]): string[] {
    const refs: string[] = [];

    for (const config of encryptionConfig) {
      const provider = config.Provider;
      if (provider && provider.KeyArn) {
        const keyArn = provider.KeyArn;

        if (typeof keyArn === 'string') {
          refs.push(keyArn);
        } else if (keyArn.Ref) {
          refs.push(keyArn.Ref);
        } else if (keyArn['Fn::GetAtt']) {
          const getAtt = keyArn['Fn::GetAtt'];
          if (Array.isArray(getAtt) && getAtt.length > 0) {
            refs.push(getAtt[0]);
          }
        }
      }
    }

    return refs;
  }

  private hasProperKmsKeyConfig(kmsKeyRefs: string[], allResources: CloudFormationResource[]): boolean {
    for (const keyRef of kmsKeyRefs) {
      const kmsKey = allResources.find(resource =>
        resource.Type === 'AWS::KMS::Key' && resource.LogicalId === keyRef
      );

      if (kmsKey) {
        // Check if key rotation is enabled
        const enableKeyRotation = kmsKey.Properties?.EnableKeyRotation;

        // If enableKeyRotation is an intrinsic function, we can't validate at scan time
        if (typeof enableKeyRotation === 'object') {
          return false;
        }

        if (enableKeyRotation !== true) {
          return false;
        }

        // Check if key policy allows EKS service
        const keyPolicy = kmsKey.Properties?.KeyPolicy;

        // If keyPolicy is an intrinsic function, we can't validate at scan time
        if (keyPolicy && typeof keyPolicy === 'object' && !Array.isArray(keyPolicy) && !keyPolicy.Statement) {
          return false;
        }

        if (keyPolicy && !this.keyPolicyAllowsEksService(keyPolicy)) {
          return false;
        }
      }
    }

    return true;
  }

  private isEksRelatedKey(resource: CloudFormationResource): boolean {
    if (this.eksKmsKeyRefs.has(resource.LogicalId)) {
      return true;
    }

    const keyPolicy = resource.Properties?.KeyPolicy;
    if (keyPolicy && this.keyPolicyAllowsEksService(keyPolicy)) {
      return true;
    }

    return false;
  }

  private keyPolicyAllowsEksService(keyPolicy: any): boolean {
    if (!keyPolicy) {
      return false;
    }

    // Check if the policy has statements
    const statements = keyPolicy.Statement;
    if (!statements) {
      return false;
    }

    const statementArray = Array.isArray(statements) ? statements : [statements];

    for (const statement of statementArray) {
      // Skip if statement is an intrinsic function
      if (typeof statement !== 'object' || !statement.Principal) {
        continue;
      }

      // Check if the statement allows the EKS service
      const principal = statement.Principal;

      if (principal.Service) {
        const service = principal.Service;

        // Skip if service is an intrinsic function
        if (typeof service === 'object' && !Array.isArray(service)) {
          continue;
        }

        if (
          (typeof service === 'string' &&
            (service.includes('eks.amazonaws.com') || service === '*')) ||
          (Array.isArray(service) &&
            (service.includes('eks.amazonaws.com') || service.includes('*')))
        ) {
          return true;
        }
      }
    }

    return false;
  }
}

export default new EKS018Rule();
