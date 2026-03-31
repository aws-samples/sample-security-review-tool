import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT6 Rule: Periodically test IoT device and solution resilience according to lifecycle policies.
 * 
 * Documentation: "A solution owner should schedule periodic penetration tests and comprehensive, 
 * end-to-end security reviews against a preselected industry standard."
 */
export class IoT006Rule extends BaseRule {
  constructor() {
    super(
      'IOT-006',
      'HIGH',
      'IoT resources lack resilience testing mechanisms',
      [
        'AWS::IoT::Thing',
        'AWS::IoT::ThingGroup'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::IoT::Thing') {
      return this.evaluateIoTThing(resource, stackName, allResources);
    }

    if (resource.Type === 'AWS::IoT::ThingGroup') {
      return this.evaluateIoTThingGroup(resource, stackName, allResources);
    }

    return null;
  }

  private evaluateIoTThing(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const hasResilienceTesting = this.hasResilienceTesting(resource, allResources);
    const hasPenetrationTesting = this.hasPenetrationTesting(resource, allResources);
    const hasSecurityReviews = this.hasSecurityReviews(resource, allResources);
    const hasOwnerAssignment = this.hasOwnerAssignment(resource);

    // Check if resilience testing is configured
    if (!hasResilienceTesting && !hasPenetrationTesting && !hasSecurityReviews) {
      const issueMessage = `${this.description} (no resilience testing mechanisms configured)`;
      const fix = 'Schedule periodic penetration tests and security reviews';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if owner is assigned for testing
    if (!hasOwnerAssignment) {
      const issueMessage = `${this.description} (no solution owner assigned for resilience testing)`;
      const fix = 'Assign a solution owner responsible for resilience testing';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    return null;
  }

  private evaluateIoTThingGroup(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if thing group has resilience testing policy
    if (!this.hasGroupResiliencePolicy(resource)) {
      const issueMessage = `${this.description} (thing group lacks resilience testing policy)`;
      const fix = 'Define resilience testing policy for the IoT thing group';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    return null;
  }

  private hasResilienceTesting(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) return false;

    const thingName = resource.Properties?.ThingName || resource.LogicalId;

    // Check for scheduled resilience testing via EventBridge
    const hasScheduledTesting = allResources.some(res => {
      if (res.Type === 'AWS::Events::Rule') {
        const ruleName = res.Properties?.Name || '';
        const scheduleExpression = res.Properties?.ScheduleExpression || '';
        
        const nameIndicatesResilience = typeof ruleName === 'string' &&
                                       (ruleName.toLowerCase().includes('resilience') ||
                                        ruleName.toLowerCase().includes('testing') ||
                                        ruleName.toLowerCase().includes('security-test'));
        
        const hasSchedule = typeof scheduleExpression === 'string' &&
                           (scheduleExpression.includes('rate(') || scheduleExpression.includes('cron('));
        
        return nameIndicatesResilience && hasSchedule;
      }
      return false;
    });

    // Check for Step Functions for resilience testing workflows
    const hasTestingWorkflow = allResources.some(res => {
      if (res.Type === 'AWS::StepFunctions::StateMachine') {
        const stateMachineName = res.Properties?.StateMachineName || res.LogicalId;
        return typeof stateMachineName === 'string' &&
               (stateMachineName.toLowerCase().includes('resilience') ||
                stateMachineName.toLowerCase().includes('testing') ||
                stateMachineName.toLowerCase().includes('security'));
      }
      return false;
    });

    // Check for resilience testing attributes
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    const hasResilienceAttributes = attributes && Object.keys(attributes).some(key =>
      key.toLowerCase().includes('resilience') ||
      key.toLowerCase().includes('testing') ||
      key.toLowerCase().includes('security-review')
    );

    return hasScheduledTesting || hasTestingWorkflow || hasResilienceAttributes;
  }

  private hasPenetrationTesting(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) return false;

    // Check for Lambda functions that perform penetration testing
    const hasPenTestLambda = allResources.some(res => {
      if (res.Type === 'AWS::Lambda::Function') {
        const functionName = res.Properties?.FunctionName || res.LogicalId;
        const environment = res.Properties?.Environment?.Variables || {};
        
        const nameIndicatesPenTest = typeof functionName === 'string' &&
                                    (functionName.toLowerCase().includes('pentest') ||
                                     functionName.toLowerCase().includes('penetration') ||
                                     functionName.toLowerCase().includes('security-test'));
        
        const envIndicatesPenTest = Object.keys(environment).some(key =>
          key.toLowerCase().includes('pentest') ||
          key.toLowerCase().includes('penetration') ||
          key.toLowerCase().includes('security_test')
        );
        
        return nameIndicatesPenTest || envIndicatesPenTest;
      }
      return false;
    });

    // Check for EventBridge rules for scheduled penetration testing
    const hasPenTestSchedule = allResources.some(res => {
      if (res.Type === 'AWS::Events::Rule') {
        const ruleName = res.Properties?.Name || '';
        const scheduleExpression = res.Properties?.ScheduleExpression || '';
        
        const nameIndicatesPenTest = typeof ruleName === 'string' &&
                                    (ruleName.toLowerCase().includes('pentest') ||
                                     ruleName.toLowerCase().includes('penetration'));
        
        const hasSchedule = typeof scheduleExpression === 'string' &&
                           scheduleExpression.includes('rate(');
        
        return nameIndicatesPenTest && hasSchedule;
      }
      return false;
    });

    return hasPenTestLambda || hasPenTestSchedule;
  }

  private hasSecurityReviews(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) return false;

    // Check for scheduled security reviews
    return allResources.some(res => {
      if (res.Type === 'AWS::Events::Rule') {
        const ruleName = res.Properties?.Name || '';
        const scheduleExpression = res.Properties?.ScheduleExpression || '';
        
        const nameIndicatesReview = typeof ruleName === 'string' &&
                                   (ruleName.toLowerCase().includes('security-review') ||
                                    ruleName.toLowerCase().includes('compliance-review') ||
                                    ruleName.toLowerCase().includes('audit'));
        
        const hasSchedule = typeof scheduleExpression === 'string' &&
                           scheduleExpression.includes('rate(');
        
        return nameIndicatesReview && hasSchedule;
      }
      return false;
    });
  }

  private hasOwnerAssignment(resource: CloudFormationResource): boolean {
    // Check for owner attributes
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    if (attributes) {
      const hasOwnerAttribute = Object.keys(attributes).some(key =>
        key.toLowerCase().includes('owner') ||
        key.toLowerCase().includes('responsible') ||
        key.toLowerCase().includes('solution-owner')
      );
      if (hasOwnerAttribute) return true;
    }

    // Check for owner tags
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      return tags.some(tag =>
        tag.Key.toLowerCase().includes('owner') ||
        tag.Key.toLowerCase().includes('responsible') ||
        tag.Key.toLowerCase().includes('solution-owner')
      );
    }

    return false;
  }

  private hasGroupResiliencePolicy(resource: CloudFormationResource): boolean {
    // Check for resilience testing policy in attributes
    const attributePayload = resource.Properties?.ThingGroupProperties?.AttributePayload;
    if (attributePayload?.Attributes) {
      const attributes = attributePayload.Attributes;
      return Object.keys(attributes).some(key =>
        key.toLowerCase().includes('resilience') ||
        key.toLowerCase().includes('testing') ||
        key.toLowerCase().includes('security-review')
      );
    }

    // Check tags for resilience policy
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      return tags.some(tag =>
        (tag.Key.toLowerCase().includes('resilience') ||
         tag.Key.toLowerCase().includes('testing')) &&
        tag.Value === 'true'
      );
    }

    return false;
  }
}

export default new IoT006Rule();