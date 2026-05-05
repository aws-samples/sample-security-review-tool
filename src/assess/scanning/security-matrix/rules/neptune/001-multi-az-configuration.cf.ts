import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Neptune001Rule extends BaseRule {
  constructor() {
    super(
      'NEPTUNE-001',
      'HIGH',
      'Neptune cluster not configured for multi-AZ deployment',
      ['AWS::Neptune::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Get cluster identifier to find associated instances
    const clusterIdentifier = resource.Properties?.DBClusterIdentifier;
    if (!clusterIdentifier) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Neptune cluster must have a valid DBClusterIdentifier to associate instances.`
      );
    }

    // Find all Neptune DB instances that belong to this cluster
    const neptuneInstances = this.findAssociatedNeptuneInstances(clusterIdentifier, allResources || []);

    if (neptuneInstances.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Create at least one Neptune DB instance for the cluster to enable basic functionality.`
      );
    }

    // Check if we have multiple instances (required for multi-AZ)
    if (neptuneInstances.length === 1) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Deploy at least one read replica in a different Availability Zone to enable multi-AZ configuration for high availability and automatic failover.`
      );
    }

    // Check if instances are distributed across multiple AZs
    const availabilityZones = this.getInstanceAvailabilityZones(neptuneInstances);

    if (availabilityZones.size < 2) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Deploy Neptune instances across at least two different Availability Zones by specifying different AvailabilityZone properties on your AWS::Neptune::DBInstance resources.`
      );
    }

    // Check if subnet group spans multiple AZs (Neptune requirement)
    const subnetGroupValidation = this.validateSubnetGroupMultiAZ(resource, stackName, allResources || []);
    if (subnetGroupValidation) {
      return subnetGroupValidation;
    }

    // All checks passed - cluster is properly configured for multi-AZ
    return null;
  }

  /**
   * Find all Neptune DB instances that belong to the specified cluster
   */
  private findAssociatedNeptuneInstances(clusterIdentifier: any, allResources: CloudFormationResource[]): CloudFormationResource[] {
    return allResources.filter(resource => {
      if (resource.Type !== 'AWS::Neptune::DBInstance') {
        return false;
      }

      const instanceClusterRef = resource.Properties?.DBClusterIdentifier;

      // Handle both direct string values and CloudFormation references
      if (typeof instanceClusterRef === 'string') {
        return instanceClusterRef === clusterIdentifier;
      }

      // Handle CloudFormation Ref functions
      if (instanceClusterRef && typeof instanceClusterRef === 'object') {
        if (instanceClusterRef.Ref || instanceClusterRef['!Ref']) {
          // This is a reference to another resource - we'll assume it matches
          // since we can't resolve references at scan time
          return true;
        }
      }

      return false;
    });
  }

  /**
   * Extract availability zones from Neptune instances
   */
  private getInstanceAvailabilityZones(instances: CloudFormationResource[]): Set<string> {
    const azs = new Set<string>();

    instances.forEach(instance => {
      const az = instance.Properties?.AvailabilityZone;

      if (typeof az === 'string') {
        azs.add(az);
      } else if (az && typeof az === 'object') {
        // Handle CloudFormation references (Ref, GetAZs, etc.)
        // We'll assume these are valid and different AZs
        if (az.Ref || az['!Ref']) {
          azs.add(`ref-${az.Ref || az['!Ref']}`);
        } else if (az['Fn::Select'] || az['!Select']) {
          // Handle selections from GetAZs
          azs.add(`select-${JSON.stringify(az)}`);
        }
      }
    });

    return azs;
  }

  /**
   * Validate that the Neptune cluster's subnet group spans multiple AZs
   */
  private validateSubnetGroupMultiAZ(clusterResource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    const subnetGroupName = clusterResource.Properties?.DBSubnetGroupName;

    if (!subnetGroupName) {
      return this.createScanResult(
        clusterResource,
        stackName,
        `${this.description}`,
        `Specify a DBSubnetGroupName that spans multiple Availability Zones.`
      );
    }

    // Find the subnet group resource
    let subnetGroup: CloudFormationResource | undefined;

    if (typeof subnetGroupName === 'object' && subnetGroupName.Ref) {
      // It's a reference to another resource in the template
      const refName = subnetGroupName.Ref;
      subnetGroup = allResources.find(r =>
        r.Type === 'AWS::Neptune::DBSubnetGroup' &&
        r.LogicalId === refName
      );
    }

    if (subnetGroup) {
      const subnetIds = subnetGroup.Properties?.SubnetIds;
      if (Array.isArray(subnetIds) && subnetIds.length < 2) {
        return this.createScanResult(
          clusterResource,
          stackName,
          `${this.description}`,
          `Configure the Neptune DB subnet group to include subnets from at least two different Availability Zones.`
        );
      }
    }

    return null;
  }
}

export default new Neptune001Rule();
