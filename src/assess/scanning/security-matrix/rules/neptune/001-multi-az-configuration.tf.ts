import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNeptune001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'NEPTUNE-001',
      'HIGH',
      'Neptune cluster not configured for multi-AZ deployment',
      ['aws_neptune_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const neptuneInstances = allResources.filter(
      r => r.type === 'aws_neptune_cluster_instance' &&
        r.values?.cluster_identifier === resource.values?.cluster_identifier
    );

    if (neptuneInstances.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Create at least one Neptune cluster instance for the cluster to enable basic functionality.`
      );
    }

    if (neptuneInstances.length === 1) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Deploy at least one read replica in a different Availability Zone to enable multi-AZ configuration for high availability.`
      );
    }

    const availabilityZones = new Set<string>();
    for (const instance of neptuneInstances) {
      const az = instance.values?.availability_zone;
      if (typeof az === 'string') {
        availabilityZones.add(az);
      }
    }

    if (availabilityZones.size > 0 && availabilityZones.size < 2) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Deploy Neptune instances across at least two different Availability Zones.`
      );
    }

    return null;
  }
}

export default new TfNeptune001Rule();
