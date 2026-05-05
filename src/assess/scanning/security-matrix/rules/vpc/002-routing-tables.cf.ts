import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * VPC2 Rule: Routing rules differ by subnet, allowing access only where required.
 * 
 * Documentation: "AWS recommends using public subnets for external-facing resources and private subnets for internal resources. 
 * For each Availability Zone, does the solution provision one public subnet and at least one private subnet by default.
 * Subnets that do not need Internet access do not have entries in routing tables that reach Internet Gateways or NAT Gateways."
 */
export class NetVpc002Rule extends BaseRule {
  constructor() {
    super(
      'NET-VPC-002',
      'HIGH',
      'Route table has insecure routing configuration',
      ['AWS::EC2::RouteTable', 'AWS::EC2::Route', 'AWS::EC2::SubnetRouteTableAssociation']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (!resource.Properties) {
      return null;
    }

    const resolver = new CloudFormationResolver(allResources);

    if (resource.Type === 'AWS::EC2::Route') {
      // Get route properties
      const routeTableId = resource.Properties.RouteTableId;
      const gatewayId = resource.Properties.GatewayId;
      const natGatewayId = resource.Properties.NatGatewayId;
      const egressOnlyInternetGatewayId = resource.Properties.EgressOnlyInternetGatewayId;
      const destinationCidrBlock = resource.Properties.DestinationCidrBlock;
      const destinationIpv6CidrBlock = resource.Properties.DestinationIpv6CidrBlock;

      // Use resolver to handle intrinsic functions
      const resolvedGatewayId = resolver.resolve(gatewayId);
      const resolvedNatGatewayId = resolver.resolve(natGatewayId);
      const resolvedEgressGatewayId = resolver.resolve(egressOnlyInternetGatewayId);
      const resolvedDestCidr = resolver.resolve(destinationCidrBlock);
      const resolvedDestIpv6Cidr = resolver.resolve(destinationIpv6CidrBlock);

      // Fail if key properties can't be resolved due to intrinsic functions
      if ((!resolvedGatewayId.isResolved && gatewayId) ||
        (!resolvedNatGatewayId.isResolved && natGatewayId) ||
        (!resolvedEgressGatewayId.isResolved && egressOnlyInternetGatewayId) ||
        (!resolvedDestCidr.isResolved && destinationCidrBlock) ||
        (!resolvedDestIpv6Cidr.isResolved && destinationIpv6CidrBlock)) {
        return this.createScanResult(
          resource,
          stackName,
          `Route contains CloudFormation intrinsic functions that cannot be evaluated at scan-time`,
          `Replace intrinsic functions with literal values or ensure they will resolve to compliant values at deployment time.`
        );
      }

      // Check if this is a default route (0.0.0.0/0 or ::/0)
      const isDefaultIpv4Route = resolvedDestCidr.isResolved && resolvedDestCidr.value === '0.0.0.0/0';
      const isDefaultIpv6Route = resolvedDestIpv6Cidr.isResolved && resolvedDestIpv6Cidr.value === '::/0';

      if (!isDefaultIpv4Route && !isDefaultIpv6Route) {
        // Not a default route, so it's not a security concern
        return null;
      }

      // Check what type of gateway this route is using
      const usesInternetGateway = this.routeUsesInternetGateway(resolvedGatewayId.value);
      const usesEgressOnlyGateway = resolvedEgressGatewayId.isResolved && !!resolvedEgressGatewayId.value;

      // If this is a default route using an Internet Gateway, we need to check
      // if the route table is associated with a private subnet
      if (usesInternetGateway && isDefaultIpv4Route) {
        // Get the route table ID
        const resolvedRouteTableId = resolver.resolve(routeTableId);
        const rtbId = resolvedRouteTableId.isResolved ? resolvedRouteTableId.value : null;

        if (rtbId) {
          // Check if this route table is associated with any private subnets
          const associatedSubnets = this.getAssociatedSubnets(rtbId, allResources, resolver);

          for (const subnetId of associatedSubnets) {
            // Check if this subnet is marked as private
            const subnet = this.findSubnetById(subnetId, allResources);

            if (subnet && this.isPrivateSubnet(subnet, resolver)) {
              return this.createScanResult(
                resource,
                stackName,
                `Private subnet ${subnetId} has a default route to an Internet Gateway`,
                `Replace the Internet Gateway with a NAT Gateway for outbound internet access from private subnets.`
              );
            }
          }
        }
      }

      // For IPv6, only Egress-Only Internet Gateways should be used for private subnets
      if (isDefaultIpv6Route && !usesEgressOnlyGateway) {
        // Get the route table ID
        const resolvedRouteTableId = resolver.resolve(routeTableId);
        const rtbId = resolvedRouteTableId.isResolved ? resolvedRouteTableId.value : null;

        if (rtbId) {
          // Check if this route table is associated with any private subnets
          const associatedSubnets = this.getAssociatedSubnets(rtbId, allResources, resolver);

          for (const subnetId of associatedSubnets) {
            // Check if this subnet is marked as private
            const subnet = this.findSubnetById(subnetId, allResources);

            if (subnet && this.isPrivateSubnet(subnet, resolver)) {
              return this.createScanResult(
                resource,
                stackName,
                `Private subnet ${subnetId} has a default IPv6 route without using an Egress-Only Internet Gateway`,
                `Replace the current gateway with an Egress-Only Internet Gateway for IPv6 traffic from private subnets.`
              );
            }
          }
        }
      }
    }

    if (resource.Type === 'AWS::EC2::RouteTable') {
      // Check if this route table has any routes
      const routes = allResources.filter(r =>
        r.Type === 'AWS::EC2::Route' &&
        this.routeReferencesRouteTable(r, resource.LogicalId, resolver)
      );

      // If no routes are found, we can't determine if it's secure
      if (routes.length === 0) {
        return null;
      }

      // Check if this route table has any default routes to an Internet Gateway
      const hasDefaultRouteToIgw = routes.some(r => {
        if (!r.Properties) {
          return false;
        }

        const gatewayId = r.Properties.GatewayId;
        const destinationCidrBlock = r.Properties.DestinationCidrBlock;

        const resolvedGatewayId = resolver.resolve(gatewayId);
        const resolvedDestCidr = resolver.resolve(destinationCidrBlock);

        return resolvedDestCidr.isResolved &&
          resolvedDestCidr.value === '0.0.0.0/0' &&
          resolvedGatewayId.isResolved &&
          this.routeUsesInternetGateway(resolvedGatewayId.value);
      });

      if (hasDefaultRouteToIgw) {
        // Check if this route table is associated with any private subnets
        const associatedSubnets = this.getAssociatedSubnets(resource.LogicalId, allResources, resolver);

        for (const subnetId of associatedSubnets) {
          // Check if this subnet is marked as private
          const subnet = this.findSubnetById(subnetId, allResources);

          if (subnet && this.isPrivateSubnet(subnet, resolver)) {
            return this.createScanResult(
              resource,
              stackName,
              `Route table has a default route to an Internet Gateway and is associated with private subnet ${subnetId}`,
              `Create a separate route table for private subnets that uses a NAT Gateway instead of an Internet Gateway for outbound internet access.`
            );
          }
        }
      }
    }

    return null;
  }


  private routeUsesInternetGateway(gatewayId: any): boolean {
    if (!gatewayId) {
      return false;
    }

    // Direct string reference to an IGW
    if (typeof gatewayId === 'string') {
      return gatewayId.includes('igw-') || gatewayId.toLowerCase().includes('internetgateway');
    }

    return false;
  }

  private getAssociatedSubnets(routeTableId: string, allResources: CloudFormationResource[], resolver: CloudFormationResolver): string[] {
    const associatedSubnets: string[] = [];

    // Find all subnet associations for this route table
    const associations = allResources.filter(r =>
      r.Type === 'AWS::EC2::SubnetRouteTableAssociation' &&
      this.associationReferencesRouteTable(r, routeTableId, resolver)
    );

    // Extract the subnet IDs from the associations
    for (const association of associations) {
      if (!association.Properties) {
        continue;
      }

      const subnetId = association.Properties.SubnetId;
      const resolvedSubnetId = resolver.resolve(subnetId);

      if (resolvedSubnetId.isResolved && typeof resolvedSubnetId.value === 'string') {
        associatedSubnets.push(resolvedSubnetId.value);
      }
    }

    return associatedSubnets;
  }

  private associationReferencesRouteTable(association: CloudFormationResource, routeTableId: string, resolver: CloudFormationResolver): boolean {
    if (!association.Properties) {
      return false;
    }

    const rtbId = association.Properties.RouteTableId;
    const resolvedRtbId = resolver.resolve(rtbId);

    // Check if the resolved value matches the route table ID
    if (resolvedRtbId.isResolved && resolvedRtbId.value === routeTableId) {
      return true;
    }

    // Check if the unresolved value references the route table ID
    if (!resolvedRtbId.isResolved && resolvedRtbId.referencedResources.includes(routeTableId)) {
      return true;
    }

    return false;
  }

  private routeReferencesRouteTable(route: CloudFormationResource, routeTableId: string, resolver: CloudFormationResolver): boolean {
    if (!route.Properties) {
      return false;
    }

    const rtbId = route.Properties.RouteTableId;
    const resolvedRtbId = resolver.resolve(rtbId);

    // Check if the resolved value matches the route table ID
    if (resolvedRtbId.isResolved && resolvedRtbId.value === routeTableId) {
      return true;
    }

    // Check if the unresolved value references the route table ID
    if (!resolvedRtbId.isResolved && resolvedRtbId.referencedResources.includes(routeTableId)) {
      return true;
    }

    return false;
  }

  private findSubnetById(subnetId: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(r => r.Type === 'AWS::EC2::Subnet' && r.LogicalId === subnetId) || null;
  }

  private isPrivateSubnet(subnet: CloudFormationResource, resolver: CloudFormationResolver): boolean {
    if (!subnet.Properties) {
      return false;
    }

    // Check if the subnet has a MapPublicIpOnLaunch property set to false
    const mapPublicIp = subnet.Properties.MapPublicIpOnLaunch;
    const resolvedMapPublicIp = resolver.resolve(mapPublicIp);

    if (resolvedMapPublicIp.isResolved && resolvedMapPublicIp.value === false) {
      return true;
    }

    // Check CIDR block - private subnets often use specific CIDR ranges
    const cidrBlock = subnet.Properties.CidrBlock;
    const resolvedCidrBlock = resolver.resolve(cidrBlock);

    if (resolvedCidrBlock.isResolved && typeof resolvedCidrBlock.value === 'string') {
      const cidr = resolvedCidrBlock.value;

      // Common private subnet CIDR patterns
      // 10.x.x.x/x with third octet >= 128 often indicates private subnet
      if (cidr.startsWith('10.') && parseInt(cidr.split('.')[2]) >= 128) {
        return true;
      }

      // 172.16.x.x-172.31.x.x with third octet >= 128 often indicates private subnet
      if (cidr.startsWith('172.') &&
        parseInt(cidr.split('.')[1]) >= 16 &&
        parseInt(cidr.split('.')[1]) <= 31 &&
        parseInt(cidr.split('.')[2]) >= 128) {
        return true;
      }

      // 192.168.x.x with third octet >= 128 often indicates private subnet
      if (cidr.startsWith('192.168.') && parseInt(cidr.split('.')[2]) >= 128) {
        return true;
      }
    }

    // If we can't determine if it's private, assume it's not
    return false;
  }
}

export default new NetVpc002Rule();
