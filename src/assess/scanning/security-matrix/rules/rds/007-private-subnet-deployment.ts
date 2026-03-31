import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { findRelatedResourcesByType } from '../../../utils/resource-relationship-utils.js';

export class Rds007Rule extends BaseRule {
  constructor() {
    super(
      'RDS-007',
      'HIGH',
      'RDS Database deployed in public subnet',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if we don't have all resources (needed to check relationships)
    if (!allResources) {
      return null;
    }

    // Check if this is an RDS instance
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Skip DB instances that belong to a DB cluster
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;
      if (dbClusterIdentifier) {
        return null; // Skip evaluation for DB instances that belong to a cluster
      }

      // Continue with evaluation for standalone DB instances
      const dbSubnetGroupName = resource.Properties?.DBSubnetGroupName;

      // If no subnet group is specified, we can't determine if it's in a public subnet
      // But since AWS requires a subnet group for VPC deployments, this likely means
      // it's using the default VPC, which could have public subnets
      if (!dbSubnetGroupName) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify a DBSubnetGroupName with private subnets only.`
        );
      }

      // Find the subnet group resource
      const subnetGroupResource = this.findSubnetGroupResource(dbSubnetGroupName, allResources);

      // If we can't find the subnet group, we can't determine if it's in a public subnet
      if (!subnetGroupResource) {
        return null;
      }

      // Check if any of the subnets in the group are public
      const isPublicSubnet = this.isSubnetGroupPublic(subnetGroupResource, allResources);

      if (isPublicSubnet) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use a subnet group with private subnets only.`
        );
      }
    }
    // Check if this is an RDS cluster
    else if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if the resource has a DBSubnetGroupName property
      const dbSubnetGroupName = resource.Properties?.DBSubnetGroupName;

      // If no subnet group is specified, we can't determine if it's in a public subnet
      // But since AWS requires a subnet group for VPC deployments, this likely means
      // it's using the default VPC, which could have public subnets
      if (!dbSubnetGroupName) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify a DBSubnetGroupName with private subnets only.`
        );
      }

      // Find the subnet group resource
      const subnetGroupResource = this.findSubnetGroupResource(dbSubnetGroupName, allResources);

      // If we can't find the subnet group, we can't determine if it's in a public subnet
      if (!subnetGroupResource) {
        return null;
      }

      // Check if any of the subnets in the group are public
      const isPublicSubnet = this.isSubnetGroupPublic(subnetGroupResource, allResources);

      if (isPublicSubnet) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use a subnet group with private subnets only.`
        );
      }
    }

    return null;
  }

  /**
   * Finds the subnet group resource based on the name or reference
   * @param subnetGroupNameOrRef The subnet group name or reference
   * @param allResources All resources in the template
   * @returns The subnet group resource or null if not found
   */
  private findSubnetGroupResource(subnetGroupNameOrRef: any, allResources: CloudFormationResource[]): CloudFormationResource | null {
    // If it's a direct reference to a resource
    if (typeof subnetGroupNameOrRef === 'object' && subnetGroupNameOrRef?.Ref) {
      const subnetGroupId = subnetGroupNameOrRef.Ref;
      return allResources.find(res =>
        res.Type === 'AWS::RDS::DBSubnetGroup' &&
        res.LogicalId === subnetGroupId
      ) || null;
    }

    // If it's a string (could be a literal name or a logical ID)
    if (typeof subnetGroupNameOrRef === 'string') {
      // First try to find by logical ID
      const subnetGroupByLogicalId = allResources.find(res =>
        res.Type === 'AWS::RDS::DBSubnetGroup' &&
        res.LogicalId === subnetGroupNameOrRef
      );

      if (subnetGroupByLogicalId) {
        return subnetGroupByLogicalId;
      }

      // If not found by logical ID, it might be a literal name
      // In this case, we can't reliably determine which subnet group it refers to
      return null;
    }

    // For other intrinsic functions, we can't reliably determine the subnet group
    return null;
  }

  /**
   * Checks if a subnet group contains any public subnets
   * @param subnetGroupResource The subnet group resource
   * @param allResources All resources in the template
   * @returns True if any subnet in the group is public, false otherwise
   */
  private isSubnetGroupPublic(subnetGroupResource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Get the subnet IDs from the subnet group
    const subnetIds = subnetGroupResource.Properties?.SubnetIds;

    if (!subnetIds || !Array.isArray(subnetIds)) {
      return false;
    }

    // Find all subnet resources referenced by the subnet group
    for (const subnetIdRef of subnetIds) {
      // If it's a direct reference to a subnet resource
      if (typeof subnetIdRef === 'object' && subnetIdRef?.Ref) {
        const subnetId = subnetIdRef.Ref;
        const subnetResource = allResources.find(res =>
          res.Type === 'AWS::EC2::Subnet' &&
          res.LogicalId === subnetId
        );

        if (subnetResource) {
          // Check if this subnet is public
          if (this.isSubnetPublic(subnetResource, allResources)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Checks if a subnet is public by looking for route table associations with routes to an Internet Gateway
   * @param subnetResource The subnet resource
   * @param allResources All resources in the template
   * @returns True if the subnet is public, false otherwise
   */
  private isSubnetPublic(subnetResource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check if the subnet has MapPublicIpOnLaunch set to true
    if (subnetResource.Properties?.MapPublicIpOnLaunch === true) {
      return true;
    }

    // Find route table associations for this subnet
    const routeTableAssociations = allResources.filter(res =>
      res.Type === 'AWS::EC2::SubnetRouteTableAssociation' &&
      res.Properties?.SubnetId &&
      (
        (typeof res.Properties.SubnetId === 'object' &&
          res.Properties.SubnetId.Ref === subnetResource.LogicalId) ||
        (typeof res.Properties.SubnetId === 'string' &&
          res.Properties.SubnetId === subnetResource.LogicalId)
      )
    );

    // Check each route table association
    for (const association of routeTableAssociations) {
      const routeTableId = association.Properties?.RouteTableId;

      if (!routeTableId) {
        continue;
      }

      // Find the route table
      let routeTableResource: CloudFormationResource | undefined;

      if (typeof routeTableId === 'object' && routeTableId.Ref) {
        routeTableResource = allResources.find(res =>
          res.Type === 'AWS::EC2::RouteTable' &&
          res.LogicalId === routeTableId.Ref
        );
      } else if (typeof routeTableId === 'string') {
        routeTableResource = allResources.find(res =>
          res.Type === 'AWS::EC2::RouteTable' &&
          res.LogicalId === routeTableId
        );
      }

      if (routeTableResource) {
        // Check if this route table has routes to an Internet Gateway
        const hasInternetGatewayRoute = this.routeTableHasInternetGatewayRoute(routeTableResource, allResources);

        if (hasInternetGatewayRoute) {
          return true;
        }
      }
    }

    // If no route table associations are found, check for the main route table
    // This is a simplification, as we can't reliably determine the main route table
    // without additional context

    // Find related VPC
    const vpcId = subnetResource.Properties?.VpcId;
    let vpcResource: CloudFormationResource | undefined;

    if (typeof vpcId === 'object' && vpcId.Ref) {
      vpcResource = allResources.find(res =>
        res.Type === 'AWS::EC2::VPC' &&
        res.LogicalId === vpcId.Ref
      );
    } else if (typeof vpcId === 'string') {
      vpcResource = allResources.find(res =>
        res.Type === 'AWS::EC2::VPC' &&
        res.LogicalId === vpcId
      );
    }

    if (vpcResource) {
      // Find route tables for this VPC
      const routeTables = allResources.filter(res =>
        res.Type === 'AWS::EC2::RouteTable' &&
        res.Properties?.VpcId &&
        (
          (typeof res.Properties.VpcId === 'object' &&
            res.Properties.VpcId.Ref === vpcResource?.LogicalId) ||
          (typeof res.Properties.VpcId === 'string' &&
            res.Properties.VpcId === vpcResource?.LogicalId)
        )
      );

      // Check if any of these route tables have routes to an Internet Gateway
      for (const routeTable of routeTables) {
        const hasInternetGatewayRoute = this.routeTableHasInternetGatewayRoute(routeTable, allResources);

        if (hasInternetGatewayRoute) {
          // This is a potential public subnet
          // But since we can't be sure this route table is associated with our subnet,
          // we'll be conservative and not flag it
        }
      }
    }

    return false;
  }

  /**
   * Checks if a route table has routes to an Internet Gateway
   * @param routeTableResource The route table resource
   * @param allResources All resources in the template
   * @returns True if the route table has routes to an Internet Gateway, false otherwise
   */
  private routeTableHasInternetGatewayRoute(routeTableResource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Find routes for this route table
    const routes = allResources.filter(res =>
      res.Type === 'AWS::EC2::Route' &&
      res.Properties?.RouteTableId &&
      (
        (typeof res.Properties.RouteTableId === 'object' &&
          res.Properties.RouteTableId.Ref === routeTableResource.LogicalId) ||
        (typeof res.Properties.RouteTableId === 'string' &&
          res.Properties.RouteTableId === routeTableResource.LogicalId)
      )
    );

    // Check if any route has a destination CIDR of 0.0.0.0/0 (default route)
    // and points to an Internet Gateway
    for (const route of routes) {
      const destinationCidr = route.Properties?.DestinationCidrBlock;
      const gatewayId = route.Properties?.GatewayId;

      if (destinationCidr === '0.0.0.0/0' && gatewayId) {
        // Check if the gateway is an Internet Gateway
        if (typeof gatewayId === 'object' && gatewayId.Ref) {
          const gateway = allResources.find(res =>
            res.Type === 'AWS::EC2::InternetGateway' &&
            res.LogicalId === gatewayId.Ref
          );

          if (gateway) {
            return true;
          }
        }
      }
    }

    return false;
  }
}

export default new Rds007Rule();
