import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk002Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-002', 'HIGH', 'MSK cluster allows plaintext communication between clients and brokers', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const clientBroker = resource.values?.encryption_info?.[0]?.encryption_in_transit?.[0]?.client_broker
        || resource.values?.encryption_info?.encryption_in_transit?.client_broker;

      if (clientBroker === 'PLAINTEXT' || clientBroker === 'TLS_PLAINTEXT') {
        return this.createScanResult(resource, projectName, this.description, 'Set encryption_info.encryption_in_transit.client_broker to "TLS" to disable plaintext communication.');
      }
    }

    return null;
  }
}

export default new TfMsk002Rule();
