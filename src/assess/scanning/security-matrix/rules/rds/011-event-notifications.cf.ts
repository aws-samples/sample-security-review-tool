import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds011Rule extends BaseRule {
  constructor() {
    super(
      'RDS-011',
      'HIGH',
      'RDS resources do not have event notifications enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBSecurityGroup', 'AWS::RDS::DBSnapshot', 'AWS::RDS::DBParameterGroup', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is one of our target RDS resource types
    if (this.appliesTo(resource.Type)) {
      // If we don't have access to all resources, we can't check for event subscriptions
      if (!allResources) {
        return null;
      }

      // Check if there are ANY RDS event subscriptions in the stack
      const hasAnyRDSEventSubscription = allResources.some(r =>
        r.Type === 'AWS::RDS::EventSubscription'
      );

      if (!hasAnyRDSEventSubscription) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Create an AWS::RDS::EventSubscription resource to enable RDS event notifications for the stack.`
        );
      }
    }

    return null;
  }
}

export default new Rds011Rule();