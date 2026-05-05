import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk008Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-008', 'HIGH', 'MSK cluster using Kafka 2.5.1+ requires documented TLS configuration for ZooKeeper nodes', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const kafkaVersion = resource.values?.kafka_version;
      if (!kafkaVersion || !this.isKafkaVersion251OrLater(kafkaVersion)) {
        return null;
      }

      const clientBroker = resource.values?.encryption_info?.[0]?.encryption_in_transit?.[0]?.client_broker
        || resource.values?.encryption_info?.encryption_in_transit?.client_broker;

      if (clientBroker !== 'TLS') {
        return this.createScanResult(resource, projectName, this.description, 'Set encryption_info.encryption_in_transit.client_broker to "TLS" and document ZooKeeper TLS configuration.');
      }
    }

    return null;
  }

  private isKafkaVersion251OrLater(version: string): boolean {
    const parts = version.split('.').map(Number);
    if (parts.length < 3) return false;
    const [major, minor, patch] = parts;
    return major > 2 || (major === 2 && minor > 5) || (major === 2 && minor === 5 && patch >= 1);
  }
}

export default new TfMsk008Rule();
