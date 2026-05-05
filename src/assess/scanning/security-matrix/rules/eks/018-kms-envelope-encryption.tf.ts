import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks018Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-018',
      'HIGH',
      'EKS cluster does not have KMS envelope encryption configured for Kubernetes secrets',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const encryptionConfig = resource.values?.encryption_config;
    if (!encryptionConfig || !Array.isArray(encryptionConfig) || encryptionConfig.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (no encryption configuration)`,
        'Configure encryption_config with a KMS key to encrypt Kubernetes secrets.'
      );
    }

    const hasSecretsEncryption = encryptionConfig.some((config: any) => {
      const resources = config.resources;
      return Array.isArray(resources) && resources.includes('secrets');
    });

    if (!hasSecretsEncryption) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (secrets not included in encryption resources)`,
        "Include 'secrets' in the resources list of encryption_config."
      );
    }

    const hasKmsKey = encryptionConfig.some((config: any) => {
      const provider = config.provider;
      if (!Array.isArray(provider) || provider.length === 0) return false;
      return provider[0]?.key_arn;
    });

    if (!hasKmsKey) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (no KMS key ARN provided)`,
        'Specify a KMS key ARN in the provider block of encryption_config.'
      );
    }

    return null;
  }
}

export default new TfEks018Rule();
