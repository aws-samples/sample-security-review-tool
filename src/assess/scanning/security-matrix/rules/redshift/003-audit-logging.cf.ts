import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift003Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-003',
      'HIGH',
      'Redshift cluster does not have audit logging enabled',
      ['AWS::Redshift::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties for any resource type
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure audit logging via AuditLogging property or parameter group.`
      );
    }

    if (resource.Type === 'AWS::Redshift::Cluster') {
      return this.evaluateCluster(resource, stackName, allResources || []);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // Check if the cluster has audit logging enabled directly via AuditLogging property
    if (resource.Properties.AuditLogging === true) {
      // Still need LoggingProperties to specify where logs go
      if (!resource.Properties.LoggingProperties || !resource.Properties.LoggingProperties.BucketName) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add LoggingProperties with BucketName to store audit logs.`
        );
      }
      return null; // Audit logging is properly configured
    }

    // Check if it has a parameter group that enables audit logging
    const paramGroupName = this.getResourceId(resource.Properties?.ClusterParameterGroupName);

    let auditLoggingEnabled = false;
    let actionMessage = '';

    if (!paramGroupName) {
      // Using default parameter group - audit logging not enabled
      actionMessage = 'Enable audit logging via AuditLogging property or specify a ClusterParameterGroupName with enable_user_activity_logging set to true';
    } else {
      // Find the parameter group resource in the same template
      const paramGroup = this.findParameterGroupByName(paramGroupName, allResources);

      if (paramGroup) {
        // Check if the parameter group has audit logging enabled
        auditLoggingEnabled = this.isParameterGroupCompliant(paramGroup);
        if (!auditLoggingEnabled) {
          actionMessage = `Set 'enable_user_activity_logging' to 'true' in parameter group '${paramGroupName}' or enable audit logging directly via AuditLogging property`;
        }
      } else {
        // External parameter group - can't verify, but assume user knows what they're doing if LoggingProperties exists
        if (resource.Properties.LoggingProperties && resource.Properties.LoggingProperties.BucketName) {
          return null; // Assume external parameter group is configured correctly if logging destination exists
        }
        actionMessage = `Ensure external parameter group '${paramGroupName}' has 'enable_user_activity_logging' set to 'true' or enable audit logging via AuditLogging property`;
      }
    }

    // If audit logging is enabled via parameter group, check for LoggingProperties
    if (auditLoggingEnabled) {
      if (!resource.Properties.LoggingProperties || !resource.Properties.LoggingProperties.BucketName) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add LoggingProperties with BucketName to store audit logs.`
        );
      }
      return null; // Fully compliant
    }

    // Not compliant - audit logging not enabled
    const fullActionMessage = actionMessage +
      (resource.Properties.LoggingProperties && resource.Properties.LoggingProperties.BucketName
        ? ''
        : ' and add LoggingProperties with BucketName to store audit logs');

    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `${fullActionMessage}.`
    );
  }

  private isParameterGroupCompliant(paramGroup: CloudFormationResource): boolean {
    const parameters = paramGroup.Properties?.Parameters;

    if (!parameters || !Array.isArray(parameters)) {
      return false;
    }

    const auditLoggingParam = parameters.find((param: any) =>
      param.ParameterName === 'enable_user_activity_logging'
    );

    if (!auditLoggingParam) {
      return false;
    }

    const auditLoggingValue = auditLoggingParam.ParameterValue;

    // Handle CloudFormation intrinsic functions - assume compliant
    if (typeof auditLoggingValue === 'object') {
      return true;
    }

    // Check if it's set to a truthy value
    return auditLoggingValue === true || auditLoggingValue === 'true' || auditLoggingValue === '1';
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

export default new Redshift003Rule();