import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ATH1 Rule: Is encryption enabled for Athena query results?
 * 
 * Documentation: "Solutions must ensure that encryption at-rest is enabled for Amazon Athena query results 
 * stored in Amazon S3 in order to secure data and meet compliance requirements for data at-rest encryption."
 */
export class ATH001Rule extends BaseRule {
  constructor() {
    super(
      'ATH-001',
      'HIGH',
      'Athena workgroup does not have encryption enabled for query results',
      ['AWS::Athena::WorkGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::Athena::WorkGroup') {
      return null;
    }

    // ATH1: Is encryption enabled for Athena query results?
    const encryptionPath = resource.Properties?.WorkGroupConfiguration?.ResultConfiguration?.EncryptionConfiguration;
    
    if (!encryptionPath) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration with EncryptionOption (SSE_S3, SSE_KMS, or CSE_KMS).`
      );
    }

    const encryptionOption = encryptionPath.EncryptionOption;
    const validOptions = ['SSE_S3', 'SSE_KMS', 'CSE_KMS'];
    
    if (!encryptionOption || !validOptions.includes(encryptionOption)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EncryptionOption to 'SSE_S3', 'SSE_KMS', or 'CSE_KMS' to enable query results encryption.`
      );
    }

    // For KMS encryption, verify KmsKey is provided
    if (['SSE_KMS', 'CSE_KMS'].includes(encryptionOption) && !encryptionPath.KmsKey) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `When using ${encryptionOption}, specify a KMS key ARN in the KmsKey property.`
      );
    }

    // Encryption is enabled - ATH1 requirement satisfied
    return null;
  }
}

export default new ATH001Rule();
