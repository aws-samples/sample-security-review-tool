import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK8 Rule: If using Apache Kafka version 2.5.1 or later, I confirm that I have documented 
 * instructions on how to use TLS with ZooKeeper nodes on the implementation guide.
 */
export class MSK008Rule extends BaseRule {
  constructor() {
    super(
      'MSK-008',
      'HIGH',
      'MSK cluster using Kafka 2.5.1+ requires documented TLS configuration for ZooKeeper nodes',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    const kafkaVersion = resource.Properties?.KafkaVersion;
    
    if (!kafkaVersion || !this.isKafkaVersion251OrLater(kafkaVersion)) {
      return null;
    }

    // For Kafka 2.5.1+, check if TLS is configured for ZooKeeper
    const encryptionInfo = resource.Properties?.EncryptionInfo;
    const encryptionInTransit = encryptionInfo?.EncryptionInTransit;
    
    if (!encryptionInTransit || encryptionInTransit.ClientBroker !== 'TLS') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure EncryptionInfo.EncryptionInTransit.ClientBroker: TLS and document ZooKeeper TLS configuration in implementation guide.`
      );
    }

    return null;
  }

  private isKafkaVersion251OrLater(version: string): boolean {
    const versionParts = version.split('.').map(Number);
    if (versionParts.length < 3) return false;
    
    const [major, minor, patch] = versionParts;
    return major > 2 || (major === 2 && minor > 5) || (major === 2 && minor === 5 && patch >= 1);
  }
}

export default new MSK008Rule();