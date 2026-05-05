import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EMR1 Rule: Is the cluster created in a private subnet within a VPC?
 * 
 * Documentation: "EMR clusters should be created in a VPC private subnet to prevent direct Internet access."
 */
export class EMR001Rule extends BaseRule {
  constructor() {
    super(
      'EMR-001',
      'HIGH',
      'EMR cluster is not configured with VPC private subnet',
      ['AWS::EMR::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::EMR::Cluster') {
      return null;
    }

    // EMR1: Is the cluster created in a private subnet within a VPC?
    const ec2SubnetId = resource.Properties?.Instances?.Ec2SubnetId;
    const ec2SubnetIds = resource.Properties?.Instances?.Ec2SubnetIds;
    
    if (!ec2SubnetId && (!ec2SubnetIds || ec2SubnetIds.length === 0)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add Instances.Ec2SubnetId or Instances.Ec2SubnetIds to place EMR cluster in VPC private subnet.`
      );
    }

    // VPC subnet is configured - EMR1 requirement satisfied
    return null;
  }
}

export default new EMR001Rule();