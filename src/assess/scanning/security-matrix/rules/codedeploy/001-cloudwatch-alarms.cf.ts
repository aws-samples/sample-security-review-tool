import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CD1 Rule: Implement Amazon CloudWatch alarms for AWS CodeDeploy resource usage and metrics
 * 
 * Orchestrated response should be done in CloudWatch, not from CodeDeploy.
 */
export class CodeDeploy001Rule extends BaseRule {
  constructor() {
    super(
      'CODEDEPLOY-001',
      'HIGH',
      'CodeDeploy application lacks CloudWatch alarms for monitoring',
      ['AWS::CodeDeploy::Application']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    const applicationName = resource.Properties?.ApplicationName || resource.LogicalId;
    const hasCloudWatchAlarms = this.hasRelatedCloudWatchAlarms(applicationName, allResources);

    if (!hasCloudWatchAlarms) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add CloudWatch alarms for CodeDeploy monitoring: create "AWS::CloudWatch::Alarm" resources with "MetricName" like "FailedDeployments", "Namespace": "AWS/CodeDeploy", and "Dimensions": [{"Name": "ApplicationName", "Value": "' + applicationName + '"}]'
      );
    }

    return null;
  }

  private hasRelatedCloudWatchAlarms(applicationName: string, resources: CloudFormationResource[]): boolean {
    return resources.some(resource => {
      if (resource.Type !== 'AWS::CloudWatch::Alarm') {
        return false;
      }

      const dimensions = resource.Properties?.Dimensions || [];
      const namespace = resource.Properties?.Namespace;

      // Check if alarm is for CodeDeploy
      const isCodeDeployAlarm = namespace === 'AWS/CodeDeploy';
      
      // Check if alarm references this application
      const referencesApplication = dimensions.some((dim: any) => 
        dim.Name === 'ApplicationName' && 
        (dim.Value === applicationName || 
         (typeof dim.Value === 'object' && dim.Value.Ref === applicationName))
      );

      return isCodeDeployAlarm && referencesApplication;
    });
  }
}

export default new CodeDeploy001Rule();