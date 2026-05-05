import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ELB4 Rule: Use at least two AZs with Cross-Zone Load Balancing
 * 
 * Solutions should use at least two subnets in different Availability Zones with the Cross-Zone Load Balancing 
 * feature enabled, ELBs can distribute the traffic evenly across all backend instances.
 */
export class Elb004Rule extends BaseRule {
  constructor() {
    super(
      'ELB-004',
      'HIGH',
      'Load balancer does not use multiple AZs or Cross-Zone Load Balancing is not enabled',
      ['AWS::ElasticLoadBalancing::LoadBalancer', 'AWS::ElasticLoadBalancingV2::LoadBalancer']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ElasticLoadBalancing::LoadBalancer') {
      // Classic Load Balancer
      const availabilityZones = resource.Properties?.AvailabilityZones;
      const subnets = resource.Properties?.Subnets;
      
      // Check if using at least 2 AZs
      const azCount = availabilityZones ? availabilityZones.length : (subnets ? subnets.length : 0);
      if (azCount < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure load balancer to use at least 2 Availability Zones by specifying multiple AvailabilityZones or Subnets`
        );
      }

      // Check Cross-Zone Load Balancing
      const crossZone = resource.Properties?.CrossZone;
      if (!crossZone) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Enable Cross-Zone Load Balancing by setting CrossZone property to true`
        );
      }
    } else if (resource.Type === 'AWS::ElasticLoadBalancingV2::LoadBalancer') {
      // Application/Network Load Balancer
      const subnets = resource.Properties?.Subnets;
      if (!subnets || !Array.isArray(subnets) || subnets.length < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure load balancer to use at least 2 subnets in different Availability Zones`
        );
      }

      // Determine if this is a Network Load Balancer
      const isNLB = resource.Properties?.Type?.toLowerCase() === 'network';
      
        // Check Cross-Zone Load Balancing attribute
        const loadBalancerAttributes = resource.Properties?.LoadBalancerAttributes || [];
        
        if (Array.isArray(loadBalancerAttributes)) {
          // Find the cross-zone load balancing attribute if it exists
          const crossZoneAttr = loadBalancerAttributes.find((attr: any) => 
            attr.Key === 'load_balancing.cross_zone.enabled'
          );
          
          // Different load balancer types have different default behaviors:
          if (isNLB) {
            // Network Load Balancers: Cross-zone is OFF by default
            // Fail if: attribute is missing OR explicitly set to false
            const isCrossZoneDisabled = !crossZoneAttr || crossZoneAttr.Value === 'false';
            
            if (isCrossZoneDisabled) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Enable Cross-Zone Load Balancing for Network Load Balancer by setting load_balancing.cross_zone.enabled to true in LoadBalancerAttributes`
              );
            }
          } else {
            // Application Load Balancers: Cross-zone is ON by default
            // Only fail if: attribute exists AND explicitly set to false
            const isCrossZoneExplicitlyDisabled = crossZoneAttr && crossZoneAttr.Value === 'false';
            
            if (isCrossZoneExplicitlyDisabled) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Enable Cross-Zone Load Balancing for Application Load Balancer by setting load_balancing.cross_zone.enabled to true in LoadBalancerAttributes`
              );
            }
          }
      } else if (isNLB) {
        // If it's an NLB and there are no LoadBalancerAttributes, cross-zone is disabled by default
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Enable Cross-Zone Load Balancing by setting load_balancing.cross_zone.enabled to true in LoadBalancerAttributes`
        );
      }
    }

    return null;
  }
}

export default new Elb004Rule();
