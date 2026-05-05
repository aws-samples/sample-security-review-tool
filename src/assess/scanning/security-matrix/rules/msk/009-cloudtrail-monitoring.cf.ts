import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK9 Rule: Are you using CloudTrail to monitor API calls?
 * 
 * Documentation: "Amazon MSK is integrated with AWS CloudTrail, a service that provides a record 
 * of actions taken by a user, role, or an AWS service in Amazon MSK. CloudTrail captures API calls as events."
 */
export class MSK009Rule extends BaseRule {
  constructor() {
    super(
      'MSK-009',
      'HIGH',
      'MSK cluster should have CloudTrail monitoring configured',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    // If no allResources provided, provide guidance about CloudTrail requirement
    if (!allResources) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail to monitor MSK API calls by adding an AWS::CloudTrail::Trail resource with management events enabled.`
      );
    }

    const cloudTrails = allResources.filter(r => r.Type === 'AWS::CloudTrail::Trail');
    if (cloudTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail to monitor MSK API calls by adding an AWS::CloudTrail::Trail resource with management events enabled`
      );
    }

    // Check if any CloudTrail has proper configuration
    for (const trail of cloudTrails) {
      const isLogging = trail.Properties?.IsLogging;
      if (isLogging === false) {
        continue;
      }

      // Check event selectors
      const eventSelectors = trail.Properties?.EventSelectors;
      if (eventSelectors && Array.isArray(eventSelectors)) {
        for (const selector of eventSelectors) {
          if (selector.IncludeManagementEvents === false) {
            continue;
          }
          return null; // Found valid CloudTrail
        }
      }

      // Check advanced event selectors
      const advancedEventSelectors = trail.Properties?.AdvancedEventSelectors;
      if (advancedEventSelectors && Array.isArray(advancedEventSelectors)) {
        for (const selector of advancedEventSelectors) {
          if (selector.FieldSelectors && Array.isArray(selector.FieldSelectors)) {
            for (const fieldSelector of selector.FieldSelectors) {
              if (fieldSelector.Field === 'eventCategory' && 
                  fieldSelector.Equals && 
                  fieldSelector.Equals.includes('Management')) {
                return null; // Found valid CloudTrail
              }
            }
          }
        }
      }

      // Default CloudTrail includes management events
      if (!eventSelectors && !advancedEventSelectors && isLogging !== false) {
        return null;
      }
    }

    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Configure CloudTrail to monitor MSK API calls by enabling management events in the CloudTrail configuration.`
    );
  }
}

export default new MSK009Rule();