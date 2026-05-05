import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import {
  hasIntrinsicFunction,
  containsPattern
} from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * EC214 Rule: Public IP addresses are associated with load balancers and not instances wherever possible
 * 
 * Documentation: "Public IPs (whether dynamic or elastic) should only be associated with EC2 instances 
 * directly in exceptional circumstances (e.g., bastion EC2 instances) and otherwise should only be 
 * associated with edge devices like NAT gateways and load balancers."
 */
export class EC2014Rule extends BaseRule {
  constructor() {
    super(
      'EC2-014',
      'MEDIUM',
      'EC2 instance has a public IP address directly associated with it',
      ['AWS::EC2::Instance', 'AWS::EC2::NetworkInterface']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::EC2::Instance') {
      // Check if the instance has a public IP
      const associatePublicIp = resource.Properties?.AssociatePublicIpAddress;

      if (this.isPublicIpEnabled(associatePublicIp)) {
        // Check if this might be a bastion host
        const isBastionHost = this.isBastionHost(resource);

        if (!isBastionHost) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Remove the AssociatePublicIpAddress property or set it to false. Use a load balancer to expose services to the internet instead of directly exposing instances.`
          );
        }
      }
    }

    if (resource.Type === 'AWS::EC2::NetworkInterface') {
      // Check if the network interface has a public IP
      const associatePublicIp = resource.Properties?.AssociatePublicIpAddress;

      if (this.isPublicIpEnabled(associatePublicIp)) {
        // Check if this might be for a bastion host
        const isBastionHost = this.isNetworkInterfaceForBastionHost(resource, allResources);

        if (!isBastionHost) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Remove the AssociatePublicIpAddress property or set it to false. Use a load balancer to expose services to the internet instead of directly exposing instances.`
          );
        }
      }
    }

    return null;
  }

  /**
   * Check if a value indicates that a public IP is enabled
   */
  private isPublicIpEnabled(value: any): boolean {
    // Direct boolean check
    if (value === true) {
      return true;
    }

    // Handle string values that might represent true
    if (typeof value === 'string' &&
      (value.toLowerCase() === 'true' || value === '1' || value === 'yes')) {
      return true;
    }

    // Handle intrinsic functions
    if (hasIntrinsicFunction(value)) {
      // Check for patterns indicating true in the intrinsic function
      if (containsPattern(value, /true|1|yes|public|elastic/i)) {
        return true;
      }

      // Check for specific parameter references that might be true
      const valueStr = JSON.stringify(value);
      if (valueStr.includes('PublicIp') ||
        valueStr.includes('ElasticIp') ||
        valueStr.includes('AssociatePublic')) {
        return true;
      }
    }

    // Handle CDK tokens
    if (value && typeof value === 'object') {
      const valueStr = JSON.stringify(value).toLowerCase();

      // Check for CDK tokens
      if (valueStr.includes('token[') || valueStr.includes('cdk')) {
        // Check for patterns indicating public IP is enabled
        if (valueStr.includes('true') ||
          valueStr.includes('public') ||
          valueStr.includes('elastic')) {
          return true;
        }
      }
    }

    return false;
  }

  private isBastionHost(instance: CloudFormationResource): boolean {
    // Check the entire instance for bastion host indicators
    const instanceStr = JSON.stringify(instance).toLowerCase();

    // Check for common bastion host indicators
    const bastionIndicators = [
      'bastion',
      'jump',
      'ssh',
      'rdp',
      'gateway',
      'remote access',
      'access server'
    ];

    if (bastionIndicators.some(indicator => instanceStr.includes(indicator))) {
      return true;
    }

    // Check security group rules for SSH/RDP ports
    const securityGroups = instance.Properties?.SecurityGroups || instance.Properties?.SecurityGroupIds || [];
    if (securityGroups) {
      const sgStr = JSON.stringify(securityGroups).toLowerCase();
      if (sgStr.includes('22') || sgStr.includes('3389') ||
        sgStr.includes('ssh') || sgStr.includes('rdp')) {
        return true;
      }
    }

    // Check UserData for SSH/bastion configuration
    const userData = instance.Properties?.UserData;
    if (userData) {
      const userDataStr = typeof userData === 'string' ?
        userData.toLowerCase() :
        JSON.stringify(userData).toLowerCase();

      if (userDataStr.includes('ssh') ||
        userDataStr.includes('bastion') ||
        userDataStr.includes('jump') ||
        userDataStr.includes('gateway')) {
        return true;
      }
    }

    return false;
  }

  private isNetworkInterfaceForBastionHost(networkInterface: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // If allResources is not provided, we can't check cross-resource references
    if (!allResources) {
      return false;
    }

    // Check the entire network interface for bastion host indicators
    const niStr = JSON.stringify(networkInterface).toLowerCase();

    // Check for common bastion host indicators
    const bastionIndicators = [
      'bastion',
      'jump',
      'ssh',
      'rdp',
      'gateway',
      'remote access',
      'access server'
    ];

    if (bastionIndicators.some(indicator => niStr.includes(indicator))) {
      return true;
    }

    // Check if the network interface is attached to an instance that's a bastion host
    const instanceId = networkInterface.Properties?.InstanceId;

    if (instanceId) {
      // Find the instance in the template
      const instance = allResources.find(r =>
        r.Type === 'AWS::EC2::Instance' &&
        (r.LogicalId === instanceId ||
          (typeof instanceId === 'object' && JSON.stringify(instanceId).includes(r.LogicalId || '')))
      );

      if (instance) {
        return this.isBastionHost(instance);
      }
    }

    // Check security group rules for SSH/RDP ports
    const securityGroups = networkInterface.Properties?.SecurityGroups || networkInterface.Properties?.Groups || [];
    if (securityGroups) {
      const sgStr = JSON.stringify(securityGroups).toLowerCase();
      if (sgStr.includes('22') || sgStr.includes('3389') ||
        sgStr.includes('ssh') || sgStr.includes('rdp')) {
        return true;
      }
    }

    // Check for subnet associations that might indicate a bastion host
    const subnetId = networkInterface.Properties?.SubnetId;
    if (subnetId) {
      const subnetStr = JSON.stringify(subnetId).toLowerCase();
      if (subnetStr.includes('public') ||
        subnetStr.includes('dmz') ||
        subnetStr.includes('bastion')) {
        return true;
      }
    }

    return false;
  }
}

export default new EC2014Rule();
