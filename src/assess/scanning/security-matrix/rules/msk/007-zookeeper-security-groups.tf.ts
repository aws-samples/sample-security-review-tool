import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk007Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-007', 'HIGH', 'MSK cluster does not have security groups configured to limit ZooKeeper access', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const brokerNodeGroupInfo = resource.values?.broker_node_group_info;
      const securityGroups = brokerNodeGroupInfo?.security_groups
        || brokerNodeGroupInfo?.[0]?.security_groups;

      if (!securityGroups || !Array.isArray(securityGroups) || securityGroups.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Configure security_groups in broker_node_group_info to limit access to ZooKeeper nodes.');
      }
    }

    return null;
  }
}

export default new TfMsk007Rule();
