import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * NEM1 Rule: Is Transit Gateway registered with AWS Network Manager for monitoring global network?
 * 
 * Documentation: "AWS Network Manager gives you centralized network monitoring and includes events and metrics to monitor the quality of your global network, both in AWS and on premises."
 */
export class NEM001Rule extends BaseRule {
  constructor() {
    super(
      'NEM-001',
      'MEDIUM',
      'Transit Gateway is not registered with AWS Network Manager for centralized monitoring',
      [
        'AWS::EC2::TransitGateway',
        'AWS::NetworkManager::GlobalNetwork',
        'AWS::NetworkManager::TransitGatewayRegistration'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    // Check if this is a Transit Gateway resource
    if (resource.Type === 'AWS::EC2::TransitGateway') {
      const transitGatewayId = resource.LogicalId;

      // Find all Global Networks in the template
      const globalNetworks = allResources.filter(r =>
        r.Type === 'AWS::NetworkManager::GlobalNetwork'
      );

      // Find all Transit Gateway Registrations in the template
      const registrations = allResources.filter(r =>
        r.Type === 'AWS::NetworkManager::TransitGatewayRegistration' &&
        this.registrationReferencesTransitGateway(r, transitGatewayId)
      );

      // If there are Global Networks but no registrations for this Transit Gateway,
      // it indicates the Transit Gateway is not registered with Network Manager
      if (globalNetworks.length > 0 && registrations.length === 0) {
        return this.createScanResult(resource, stackName,
          `Transit Gateway ${resource.LogicalId} is not registered with AWS Network Manager`,
          `Register the Transit Gateway with AWS Network Manager using AWS::NetworkManager::TransitGatewayRegistration ` +
          `to enable centralized monitoring of your global network.`);
      }

      // If there are no Global Networks at all, suggest creating one and registering the Transit Gateway
      if (globalNetworks.length === 0) {
        return this.createScanResult(resource, stackName,
          `No AWS Network Manager Global Network found for Transit Gateway ${resource.LogicalId}`,
          `Create an AWS::NetworkManager::GlobalNetwork and register the Transit Gateway using ` +
          `AWS::NetworkManager::TransitGatewayRegistration to enable centralized monitoring of your global network.`);
      }
    }

    // Check if this is a Global Network resource
    if (resource.Type === 'AWS::NetworkManager::GlobalNetwork') {
      const globalNetworkId = resource.LogicalId;

      // Find all Transit Gateways in the template
      const transitGateways = allResources.filter(r =>
        r.Type === 'AWS::EC2::TransitGateway'
      );

      // Find all Transit Gateway Registrations for this Global Network
      const registrations = allResources.filter(r =>
        r.Type === 'AWS::NetworkManager::TransitGatewayRegistration' &&
        this.registrationReferencesGlobalNetwork(r, globalNetworkId)
      );

      // If there are Transit Gateways but not all are registered with this Global Network,
      // it indicates some Transit Gateways are not registered with Network Manager
      if (transitGateways.length > registrations.length) {
        return this.createScanResult(resource, stackName,
          `Not all Transit Gateways are registered with AWS Network Manager Global Network ${resource.LogicalId}`,
          `Register all Transit Gateways with AWS Network Manager using AWS::NetworkManager::TransitGatewayRegistration ` +
          `to enable centralized monitoring of your global network.`);
      }
    }

    return null;
  }

  private registrationReferencesTransitGateway(registration: CloudFormationResource, transitGatewayId: string): boolean {
    if (!registration.Properties) {
      return false;
    }

    const tgwId = registration.Properties.TransitGatewayArn;
    return this.referencesResource(tgwId, transitGatewayId);
  }

  private registrationReferencesGlobalNetwork(registration: CloudFormationResource, globalNetworkId: string): boolean {
    if (!registration.Properties) {
      return false;
    }

    const gnId = registration.Properties.GlobalNetworkId;
    return this.referencesResource(gnId, globalNetworkId);
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

export default new NEM001Rule();
