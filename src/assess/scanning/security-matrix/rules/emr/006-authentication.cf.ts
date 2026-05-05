import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EMR6 Rule: Is the solution implementing authentication to the cluster via customer created EC2 Key Pair or Kerberos?
 * 
 * Documentation: "Solutions must implement authentication to the cluster. SSH clients can use an Amazon EC2 key pair 
 * to authenticate to cluster instances. Alternatively, with Amazon EMR release version 5.10.0 or later, solutions can 
 * configure Kerberos to authenticate users and SSH connections to the master node."
 */
export class EMR006Rule extends BaseRule {
  constructor() {
    super(
      'EMR-006',
      'HIGH',
      'EMR cluster does not have authentication configured (EC2 Key Pair or Kerberos)',
      ['AWS::EMR::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::EMR::Cluster') {
      return null;
    }

    // EMR6: Is authentication implemented via EC2 Key Pair or Kerberos?
    const ec2KeyName = resource.Properties?.Instances?.Ec2KeyName;
    const kerberosAttributes = resource.Properties?.KerberosAttributes;
    
    if (!ec2KeyName && !kerberosAttributes) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add Instances.Ec2KeyName for SSH key authentication or KerberosAttributes for Kerberos authentication.`
      );
    }

    // Authentication is configured - EMR6 requirement satisfied
    return null;
  }
}

export default new EMR006Rule();