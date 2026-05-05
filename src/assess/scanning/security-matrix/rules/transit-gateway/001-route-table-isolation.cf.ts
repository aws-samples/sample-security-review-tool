import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * TG-001 Rule: Transit Gateway route tables have been configured to isolate VPCs in a given region.
 * 
 * Documentation: "Use Transit Gateway routing tables to isolate them wherever needed. 
 * There is a valid case for creating multiple Transit Gateways purely to limit misconfiguration blast radius."
 */
export class TG001Rule extends BaseRule {
  constructor() {
    super(
      'TG-001',
      'HIGH',
      'Transit Gateway configuration does not properly isolate VPCs using separate route tables',
      [
        'AWS::EC2::TransitGateway',
        'AWS::EC2::TransitGatewayRouteTable',
        'AWS::EC2::TransitGatewayAttachment'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    // Check Transit Gateway configuration
    if (resource.Type === 'AWS::EC2::TransitGateway') {
      // Check if default route table association is disabled
      // This is a best practice to ensure explicit route table associations
      const defaultRouteTableAssociation = resource.Properties?.DefaultRouteTableAssociation;
      if (defaultRouteTableAssociation === 'enable') {
        return this.createScanResult(resource, stackName,
          `Transit Gateway ${resource.LogicalId} has default route table association enabled`,
          `Disable default route table association and create explicit route tables for VPC isolation.`);
      }

      // Check if default route table propagation is disabled
      // This is a best practice to ensure explicit route propagation control
      const defaultRouteTablePropagation = resource.Properties?.DefaultRouteTablePropagation;
      if (defaultRouteTablePropagation === 'enable') {
        return this.createScanResult(resource, stackName,
          `Transit Gateway ${resource.LogicalId} has default route table propagation enabled`,
          `Disable default route table propagation and create explicit route propagation for controlled connectivity.`);
      }

      // Find all route tables associated with this Transit Gateway
      const transitGatewayId = resource.LogicalId;
      const routeTables = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGatewayRouteTable' &&
        this.routeTableReferencesTransitGateway(r, transitGatewayId)
      );

      // Find all VPC attachments to this Transit Gateway
      const vpcAttachments = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGatewayAttachment' &&
        this.attachmentReferencesTransitGateway(r, transitGatewayId) &&
        this.isVpcAttachment(r)
      );

      // If we have multiple VPC attachments but only one route table, it might indicate lack of isolation
      if (vpcAttachments.length > 1 && routeTables.length < 2) {
        return this.createScanResult(resource, stackName,
          `Transit Gateway ${resource.LogicalId} has ${vpcAttachments.length} VPC attachments but only ${routeTables.length} route table(s)`,
          `Create separate route tables for different security domains to ensure proper VPC isolation.`);
      }

      // Check for route table associations and propagations
      const associations = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGatewayRouteTableAssociation'
      );

      const propagations = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGatewayRouteTablePropagation'
      );

      // If we have multiple VPC attachments but no explicit associations or propagations,
      // it might indicate lack of proper isolation configuration
      if (vpcAttachments.length > 1 && associations.length === 0) {
        return this.createScanResult(resource, stackName,
          `Transit Gateway ${resource.LogicalId} has multiple VPC attachments but no explicit route table associations`,
          `Create explicit route table associations to ensure proper VPC isolation.`);
      }
    }

    // Check Transit Gateway Route Table configuration
    if (resource.Type === 'AWS::EC2::TransitGatewayRouteTable') {
      // Check if there are routes that might compromise isolation
      const routes = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGatewayRoute' &&
        this.routeReferencesRouteTable(r, resource.LogicalId)
      );

      // Look for overly permissive routes (e.g., 0.0.0.0/0)
      for (const route of routes) {
        const cidrBlock = route.Properties?.DestinationCidrBlock;
        if (cidrBlock === '0.0.0.0/0') {
          return this.createScanResult(resource, stackName,
            `Transit Gateway Route Table ${resource.LogicalId} contains an overly permissive route (0.0.0.0/0)`,
            `Use more specific CIDR blocks to limit connectivity between VPCs.`);
        }
      }
    }

    return null;
  }

  private routeTableReferencesTransitGateway(routeTable: CloudFormationResource, transitGatewayId: string): boolean {
    if (!routeTable.Properties) {
      return false;
    }

    const tgwId = routeTable.Properties.TransitGatewayId;
    return this.referencesResource(tgwId, transitGatewayId);
  }

  private attachmentReferencesTransitGateway(attachment: CloudFormationResource, transitGatewayId: string): boolean {
    if (!attachment.Properties) {
      return false;
    }

    const tgwId = attachment.Properties.TransitGatewayId;
    return this.referencesResource(tgwId, transitGatewayId);
  }

  private isVpcAttachment(attachment: CloudFormationResource): boolean {
    if (!attachment.Properties) {
      return false;
    }

    // Check if the attachment has a VpcId property
    return attachment.Properties.VpcId !== undefined;
  }

  private routeReferencesRouteTable(route: CloudFormationResource, routeTableId: string): boolean {
    if (!route.Properties) {
      return false;
    }

    const rtId = route.Properties.TransitGatewayRouteTableId;
    return this.referencesResource(rtId, routeTableId);
  }

  /**
   * Checks if a value references a specific resource ID, handling various CloudFormation
   * intrinsic functions and CDK-generated reference patterns.
   * 
   * @param value The value to check (could be a string, object with Ref, GetAtt, Sub, etc.)
   * @param resourceId The resource ID to check against
   * @returns true if the value references the resource ID, false otherwise
   */
  private referencesResource(value: any, resourceId: string): boolean {
    // Handle null/undefined case
    if (value === null || value === undefined) {
      return false;
    }

    // Direct string reference
    if (typeof value === 'string' && value === resourceId) {
      return true;
    }

    // Not an object or is an array, can't be a reference
    if (typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    // Reference using Ref
    if (value.Ref === resourceId) {
      return true;
    }

    // Reference using GetAtt
    if (value['Fn::GetAtt'] &&
      Array.isArray(value['Fn::GetAtt']) &&
      value['Fn::GetAtt'].length >= 1 &&
      value['Fn::GetAtt'][0] === resourceId) {
      return true;
    }

    // Reference using Sub with ${resourceId} pattern
    if (value['Fn::Sub'] && typeof value['Fn::Sub'] === 'string') {
      if (value['Fn::Sub'].includes(`\${${resourceId}}`) ||
        value['Fn::Sub'].includes(`\${${resourceId}.`)) {
        return true;
      }
    }

    // Reference using Sub with array pattern [string, {map}]
    if (value['Fn::Sub'] &&
      Array.isArray(value['Fn::Sub']) &&
      value['Fn::Sub'].length === 2 &&
      typeof value['Fn::Sub'][0] === 'string' &&
      typeof value['Fn::Sub'][1] === 'object') {

      const template = value['Fn::Sub'][0];
      const variables = value['Fn::Sub'][1];

      // Check if the template contains the resource ID
      if (template.includes(`\${${resourceId}}`) || template.includes(`\${${resourceId}.`)) {
        return true;
      }

      // Check if any of the variable values reference the resource ID
      for (const varName in variables) {
        if (this.referencesResource(variables[varName], resourceId)) {
          return true;
        }
      }
    }

    // Reference using ImportValue that might import a value related to the resource
    if (value['Fn::ImportValue'] &&
      ((typeof value['Fn::ImportValue'] === 'string' && value['Fn::ImportValue'].includes(resourceId)) ||
        this.referencesResource(value['Fn::ImportValue'], resourceId))) {
      return true;
    }

    // Handle nested references in Join
    if (value['Fn::Join'] &&
      Array.isArray(value['Fn::Join']) &&
      value['Fn::Join'].length === 2 &&
      Array.isArray(value['Fn::Join'][1])) {

      const parts = value['Fn::Join'][1];
      for (const part of parts) {
        if (this.referencesResource(part, resourceId)) {
          return true;
        }
      }
    }

    // Handle CDK token references which might contain the resource ID in various formats
    // CDK often generates complex nested structures with tokens
    if (value['Fn::GetAtt'] && Array.isArray(value['Fn::GetAtt'])) {
      const firstPart = value['Fn::GetAtt'][0];
      if (typeof firstPart === 'string' && firstPart.includes(resourceId)) {
        return true;
      }
    }

    // Check for CDK token patterns in any property
    for (const key in value) {
      const prop = value[key];

      // Skip if not an object or is null
      if (!prop || typeof prop !== 'object') {
        continue;
      }

      // Check for nested references
      if (this.referencesResource(prop, resourceId)) {
        return true;
      }
    }

    return false;
  }
}

export default new TG001Rule();
