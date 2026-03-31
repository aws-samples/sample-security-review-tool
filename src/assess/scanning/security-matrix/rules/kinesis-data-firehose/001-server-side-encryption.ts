import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * KDF1 Rule: Is server-side encryption (SSE) enabled for the delivery stream?
 * 
 * Documentation: "Encryption can be enabled by using the StartDeliveryStreamEncryption operation 
 * or setting the DeliveryStreamEncryptionConfigurationInput property in CloudFormation."
 */
export class KDF001Rule extends BaseRule {
  constructor() {
    super(
      'KDF-001',
      'HIGH',
      'Kinesis Data Firehose delivery stream does not have server-side encryption enabled',
      ['AWS::KinesisFirehose::DeliveryStream']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::KinesisFirehose::DeliveryStream') {
      return null;
    }

    // KDF1: Is server-side encryption (SSE) enabled for the delivery stream?
    const encryptionConfiguration = resource.Properties?.DeliveryStreamEncryptionConfigurationInput;
    
    if (!encryptionConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add DeliveryStreamEncryptionConfigurationInput with KeyType 'AWS_OWNED_CMK' or 'CUSTOMER_MANAGED_CMK'.`
      );
    }

    const keyType = encryptionConfiguration.KeyType;
    const validKeyTypes = ['AWS_OWNED_CMK', 'CUSTOMER_MANAGED_CMK'];
    
    if (!keyType || !validKeyTypes.includes(keyType)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set KeyType to 'AWS_OWNED_CMK' or 'CUSTOMER_MANAGED_CMK' in DeliveryStreamEncryptionConfigurationInput.`
      );
    }

    // For customer managed CMK, verify KeyARN is provided
    if (keyType === 'CUSTOMER_MANAGED_CMK' && !encryptionConfiguration.KeyARN) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `When using CUSTOMER_MANAGED_CMK, specify KeyARN in DeliveryStreamEncryptionConfigurationInput.`
      );
    }

    // Server-side encryption is enabled - KDF1 requirement satisfied
    return null;
  }
}

export default new KDF001Rule();