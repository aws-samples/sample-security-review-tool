import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift006Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-006',
      'MEDIUM',
      'Redshift cluster does not have user activity logging enabled',
      ['AWS::Redshift::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure database audit logging and set 'enable_user_activity_logging' to true in a non-default parameter group.`
      );
    }

    if (resource.Type === 'AWS::Redshift::Cluster') {
      return this.evaluateCluster(resource, stackName, allResources || []);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // First check: Database audit logging must be enabled
    const hasAuditLogging = this.hasAuditLoggingEnabled(resource);

    // Second check: Must have a non-default parameter group with enable_user_activity_logging=true
    const paramGroupCompliance = this.checkParameterGroupCompliance(resource, allResources);

    // Build error message based on what's missing
    let issues: string[] = [];

    if (!hasAuditLogging) {
      issues.push('enable database audit logging (via LoggingProperties or AuditLogging property)');
    }

    if (paramGroupCompliance.hasIssue) {
      issues.push(paramGroupCompliance.issue!);
    }

    if (issues.length > 0) {
      const actionMessage = `${issues.join(' and ')}.`;
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        actionMessage
      );
    }

    // Both requirements met - compliant
    return null;
  }

  private hasAuditLoggingEnabled(resource: CloudFormationResource): boolean {
    // Check for direct AuditLogging property
    if (resource.Properties.AuditLogging === true) {
      return true;
    }

    // Check for LoggingProperties (which enables audit logging)
    const loggingProperties = resource.Properties.LoggingProperties;
    if (loggingProperties && loggingProperties.BucketName) {
      return true;
    }

    return false;
  }

  private checkParameterGroupCompliance(resource: CloudFormationResource, allResources: CloudFormationResource[]): { hasIssue: boolean, issue?: string } {
    const paramGroupName = this.getResourceId(resource.Properties?.ClusterParameterGroupName);

    // If no parameter group specified, using default (which can't be modified)
    if (!paramGroupName) {
      return {
        hasIssue: true,
        issue: "specify a non-default ClusterParameterGroupName with 'enable_user_activity_logging' set to true"
      };
    }

    // Check if it's referencing the default parameter group
    if (typeof paramGroupName === 'string' && paramGroupName.toLowerCase().includes('default')) {
      return {
        hasIssue: true,
        issue: "use a non-default parameter group (default parameter groups cannot be modified)"
      };
    }

    // Find the parameter group resource in the same template
    const paramGroup = this.findParameterGroupByName(paramGroupName, allResources);

    if (paramGroup) {
      // Check if the parameter group has enable_user_activity_logging=true
      const hasUserActivityLogging = this.isUserActivityLoggingEnabled(paramGroup);

      if (!hasUserActivityLogging) {
        return {
          hasIssue: true,
          issue: `set 'enable_user_activity_logging' to true in parameter group '${paramGroupName}'`
        };
      }

      return { hasIssue: false }; // Parameter group is compliant
    }

    // External parameter group - can't verify, but warn about requirement
    return {
      hasIssue: true,
      issue: `ensure external parameter group '${paramGroupName}' has 'enable_user_activity_logging' set to true`
    };
  }

  private isUserActivityLoggingEnabled(paramGroup: CloudFormationResource): boolean {
    const parameters = paramGroup.Properties?.Parameters;

    if (!parameters || !Array.isArray(parameters)) {
      return false;
    }

    const userActivityParam = parameters.find((param: any) =>
      param.ParameterName === 'enable_user_activity_logging'
    );

    if (!userActivityParam) {
      return false;
    }

    const paramValue = userActivityParam.ParameterValue;

    // Handle CloudFormation intrinsic functions - assume compliant
    if (typeof paramValue === 'object') {
      return true;
    }

    // Check if it's set to a truthy value
    return paramValue === true || paramValue === 'true' || paramValue === '1';
  }

  private findParameterGroupByName(name: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(r =>
      r.Type === 'AWS::Redshift::ClusterParameterGroup' &&
      (r.LogicalId === name || r.Properties?.ParameterGroupName === name)
    ) || null;
  }

  private getResourceId(value: any): string | null {
    if (typeof value === 'string') {
      return value;
    }

    if (typeof value === 'object' && value?.Ref) {
      return value.Ref;
    }

    return null;
  }
}

export default new Redshift006Rule();