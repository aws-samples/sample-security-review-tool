import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK2 Rule: For communication between clients and brokers, I confirm that I'm not using plaintext communication.
 */
export class MSK002Rule extends BaseRule {
  constructor() {
    super(
      'MSK-002',
      'HIGH',
      'MSK cluster allows plaintext communication between clients and brokers',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    const encryptionInfo = resource.Properties?.EncryptionInfo;
    const encryptionInTransit = encryptionInfo?.EncryptionInTransit;
    const clientBroker = encryptionInTransit?.ClientBroker;

    if (clientBroker === 'PLAINTEXT' || clientBroker === 'TLS_PLAINTEXT') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EncryptionInfo.EncryptionInTransit.ClientBroker to 'TLS' to disable plaintext communication.`
      );
    }

    return null;
  }
}

export default new MSK002Rule();