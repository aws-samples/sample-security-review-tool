import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ELB6 Rule: Associate ELB with secure security groups
 * 
 * All solution load balancers should be associated with valid and secure security groups 
 * that restrict access only to the ports defined within the load balancers listeners configuration.
 */
export class Elb006Rule extends BaseRule {
  constructor() {
    super(
      'ELB-006',
      'HIGH',
      'Load balancer security groups allow overly permissive access',
      ['AWS::ElasticLoadBalancing::LoadBalancer', 'AWS::ElasticLoadBalancingV2::LoadBalancer']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    let securityGroups: string[] = [];
    let listenerPorts: number[] = [];

    if (resource.Type === 'AWS::ElasticLoadBalancing::LoadBalancer') {
      // Classic Load Balancer
      securityGroups = resource.Properties?.SecurityGroups || [];
      const listeners = resource.Properties?.Listeners || [];
      listenerPorts = listeners.map((listener: any) => parseInt(listener.LoadBalancerPort));
    } else if (resource.Type === 'AWS::ElasticLoadBalancingV2::LoadBalancer') {
      // Application/Network Load Balancer
      securityGroups = resource.Properties?.SecurityGroups || [];
      
      // Find associated listeners to get ports
      const listeners = allResources.filter(r => 
        r.Type === 'AWS::ElasticLoadBalancingV2::Listener' &&
        this.isListenerForLoadBalancer(r, resource)
      );
      
      listenerPorts = listeners.map((listener: any) => 
        parseInt(listener.Properties?.Port)
      ).filter(port => !isNaN(port));
    }

    if (securityGroups.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Associate load balancer with appropriate security groups that restrict access to listener ports only`
      );
    }

    // Check each security group for overly permissive rules
    for (const sgRef of securityGroups) {
      const sg = this.findSecurityGroup(sgRef, allResources);
      if (sg) {
        const issues = this.checkSecurityGroupRules(sg, listenerPorts);
        if (issues.length > 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (${issues.join(', ')})`,
            `Restrict security group ingress rules to only allow necessary ports (${listenerPorts.join(', ')}) and limit source IP ranges`
          );
        }
      }
    }

    return null;
  }

  private isListenerForLoadBalancer(listener: CloudFormationResource, loadBalancer: CloudFormationResource): boolean {
    const loadBalancerArn = listener.Properties?.LoadBalancerArn;
    if (!loadBalancerArn) return false;

    // Handle Ref
    if (typeof loadBalancerArn === 'object' && loadBalancerArn.Ref === loadBalancer.LogicalId) {
      return true;
    }

    return false;
  }

  private findSecurityGroup(sgRef: string, resources: CloudFormationResource[]): CloudFormationResource | null {
    // Handle direct reference
    if (typeof sgRef === 'string') {
      return resources.find(r => 
        r.Type === 'AWS::EC2::SecurityGroup' && r.LogicalId === sgRef
      ) || null;
    }

    // Handle Ref object
    if (typeof sgRef === 'object' && (sgRef as any).Ref) {
      const refId = (sgRef as any).Ref;
      return resources.find(r => 
        r.Type === 'AWS::EC2::SecurityGroup' && r.LogicalId === refId
      ) || null;
    }

    return null;
  }

  private checkSecurityGroupRules(sg: CloudFormationResource, allowedPorts: number[]): string[] {
    const issues: string[] = [];
    const ingressRules = sg.Properties?.SecurityGroupIngress || [];

    for (const rule of ingressRules) {
      // Check for overly broad source (0.0.0.0/0)
      if (rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0') {
        const fromPort = parseInt(rule.FromPort);
        const toPort = parseInt(rule.ToPort);

        // If rule allows all ports or ports not in listener configuration
        if (isNaN(fromPort) || isNaN(toPort) || 
            fromPort === 0 || toPort === 65535 ||
            !allowedPorts.some(port => port >= fromPort && port <= toPort)) {
          issues.push('overly broad source IP range');
        }
      }

      // Check for overly broad port ranges
      const fromPort = parseInt(rule.FromPort);
      const toPort = parseInt(rule.ToPort);
      if (!isNaN(fromPort) && !isNaN(toPort) && (toPort - fromPort > 100)) {
        issues.push('overly broad port range');
      }
    }

    return [...new Set(issues)]; // Remove duplicates
  }
}

export default new Elb006Rule();