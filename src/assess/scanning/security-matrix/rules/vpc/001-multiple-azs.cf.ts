import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * VPC1 Rule: Multiple availability zones are used for high availability where required.
 * 
 * Documentation: "AWS recommends maximizing your use of Availability Zones to isolate a data center outage. 
 * Availability Zones are geographically distributed within a region and spaced for best insulation and stability 
 * in the event of a natural disaster."
 */
export class NetVpc001Rule extends BaseRule {
  constructor() {
    super(
      'NET-VPC-001',
      'HIGH',
      'VPC configuration does not use multiple availability zones',
      ['AWS::EC2::VPC']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::EC2::VPC') {
      const vpcId = resource.LogicalId;
      const resolver = new CloudFormationResolver(allResources);

      // Find all subnets associated with this VPC
      const associatedSubnets = allResources.filter(r =>
        r.Type === 'AWS::EC2::Subnet' &&
        this.subnetReferencesVpc(r, vpcId, resolver)
      );

      // If no subnets are found, we can't determine AZ coverage
      if (associatedSubnets.length === 0) {
        return null;
      }

      // Extract AZ information from subnets
      const azs = new Set<string>();
      const azIds = new Set<string>();
      let hasIntrinsicAzs = false;

      for (const subnet of associatedSubnets) {
        if (!subnet.Properties) {
          continue;
        }

        const availabilityZone = subnet.Properties.AvailabilityZone;
        const availabilityZoneId = subnet.Properties.AvailabilityZoneId;

        // Use resolver to handle AZ values
        const resolvedAz = resolver.resolve(availabilityZone);
        const resolvedAzId = resolver.resolve(availabilityZoneId);

        // Handle resolved string AZs
        if (resolvedAz.isResolved && typeof resolvedAz.value === 'string') {
          azs.add(resolvedAz.value);
        } else if (availabilityZone && !resolvedAz.isResolved) {
          hasIntrinsicAzs = true;
        }

        // Handle resolved string AZ IDs
        if (resolvedAzId.isResolved && typeof resolvedAzId.value === 'string') {
          azIds.add(resolvedAzId.value);
        } else if (availabilityZoneId && !resolvedAzId.isResolved) {
          hasIntrinsicAzs = true;
        }
      }

      // If we have intrinsic AZ references, analyze them more carefully
      if (hasIntrinsicAzs) {
        // Check if there are multiple subnets with intrinsic AZs
        const subnetsWithIntrinsicAzs = associatedSubnets.filter(subnet => {
          const az = subnet.Properties?.AvailabilityZone;
          const azId = subnet.Properties?.AvailabilityZoneId;

          const resolvedAz = resolver.resolve(az);
          const resolvedAzId = resolver.resolve(azId);

          return (az && !resolvedAz.isResolved) || (azId && !resolvedAzId.isResolved);
        });

        // Check for Fn::GetAZs usage and verify it's likely to return multiple AZs
        const getAzsUsage = this.analyzeGetAzsUsage(associatedSubnets, resolver);
        if (getAzsUsage.usesGetAzs && getAzsUsage.likelyMultipleAzs) {
          return null; // Using Fn::GetAZs in a way that likely spans multiple AZs
        }

        // If we have at least 2 subnets with intrinsic AZs and they have different indices
        // (e.g., Fn::Select with different indices), assume they're using multiple AZs
        if (subnetsWithIntrinsicAzs.length >= 2 && this.hasDistinctAzSelections(subnetsWithIntrinsicAzs, resolver)) {
          return null;
        }

        // If we can't determine if the VPC uses multiple AZs due to intrinsic functions, fail the rule
        return this.createScanResult(
          resource,
          stackName,
          `VPC ${vpcId} uses CloudFormation intrinsic functions for availability zones that cannot be evaluated at scan-time`,
          `Replace intrinsic functions with literal values or ensure they will resolve to multiple availability zones at deployment time.`
        );
      }

      // Check if we have multiple AZs
      const totalUniqueAzs = azs.size + azIds.size;

      if (totalUniqueAzs < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `VPC ${vpcId} has subnets in only ${totalUniqueAzs} availability zone(s)`,
          `Create subnets in at least two different availability zones to ensure high availability.`
        );
      }
    }

    return null;
  }

  private subnetReferencesVpc(subnet: CloudFormationResource, vpcId: string, resolver: CloudFormationResolver): boolean {
    if (!subnet.Properties) {
      return false;
    }

    const subnetVpcId = subnet.Properties.VpcId;
    const resolved = resolver.resolve(subnetVpcId);

    // If resolved, check if it matches the VPC ID
    if (resolved.isResolved && resolved.value === vpcId) {
      return true;
    }

    // If not resolved, check if it references the VPC ID
    if (!resolved.isResolved && resolved.referencedResources.includes(vpcId)) {
      return true;
    }

    return false;
  }

  private analyzeGetAzsUsage(subnets: CloudFormationResource[], resolver: CloudFormationResolver): { usesGetAzs: boolean; likelyMultipleAzs: boolean } {
    let usesGetAzs = false;
    let likelyMultipleAzs = false;
    const selectIndices = new Set<number>();

    for (const subnet of subnets) {
      const az = subnet.Properties?.AvailabilityZone;

      // Check for Fn::GetAZs usage
      if (az && typeof az === 'object') {
        // Direct Fn::GetAZs usage
        if (az['Fn::GetAZs'] !== undefined) {
          usesGetAzs = true;
          likelyMultipleAzs = true; // Fn::GetAZs typically returns multiple AZs
        }

        // Fn::Select with Fn::GetAZs
        if (az['Fn::Select'] && Array.isArray(az['Fn::Select']) && az['Fn::Select'].length >= 2) {
          const index = az['Fn::Select'][0];
          const azList = az['Fn::Select'][1];

          if (typeof azList === 'object' && !Array.isArray(azList) && azList['Fn::GetAZs'] !== undefined) {
            usesGetAzs = true;

            // Track the select index
            if (typeof index === 'number') {
              selectIndices.add(index);
            } else if (typeof index === 'string' && !isNaN(parseInt(index))) {
              selectIndices.add(parseInt(index));
            }
          }
        }
      }
    }

    // If we have multiple distinct indices for Fn::Select, it's likely multi-AZ
    if (selectIndices.size >= 2) {
      likelyMultipleAzs = true;
    }

    return { usesGetAzs, likelyMultipleAzs };
  }

  private hasDistinctAzSelections(subnets: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
    const indices = new Set<string | number>();

    for (const subnet of subnets) {
      const az = subnet.Properties?.AvailabilityZone;

      // Check for Fn::Select with an index
      if (az && typeof az === 'object' && az['Fn::Select'] &&
        Array.isArray(az['Fn::Select']) && az['Fn::Select'].length >= 2) {
        const index = az['Fn::Select'][0];

        // If the index is a number or string, add it to our set
        if (typeof index === 'number' || typeof index === 'string') {
          indices.add(index);
        }
      }
    }

    // If we have multiple distinct indices, it's likely multi-AZ
    return indices.size >= 2;
  }
}

export default new NetVpc001Rule();
