import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK7 Rule: I confirm that I'm using security groups to limit access to ZooKeeper nodes
 * 
 * Documentation: "You can limit access to the Apache ZooKeeper nodes that are part a cluster by assigning a separate security group to them."
 */
export class MSK007Rule extends BaseRule {
  constructor() {
    super(
      'MSK-007',
      'HIGH',
      'MSK cluster does not have security groups configured to limit ZooKeeper access',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    // Check if BrokerNodeGroupInfo is configured
    const brokerNodeGroupInfo = resource.Properties?.BrokerNodeGroupInfo;
    if (!brokerNodeGroupInfo) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure BrokerNodeGroupInfo with SecurityGroups to limit access to ZooKeeper nodes.`
      );
    }

    // Check if SecurityGroups are specified
    const securityGroups = brokerNodeGroupInfo.SecurityGroups;
    if (!securityGroups || !Array.isArray(securityGroups) || securityGroups.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure SecurityGroups in BrokerNodeGroupInfo to limit access to ZooKeeper nodes.`
      );
    }

    // If security groups are configured, assume they properly limit ZooKeeper access
    // (detailed security group rule validation would require checking the actual security group resources)
    return null;
  }
}

export default new MSK007Rule();