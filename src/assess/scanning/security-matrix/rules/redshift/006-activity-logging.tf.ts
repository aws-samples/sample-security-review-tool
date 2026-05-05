import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift006Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-006',
      'MEDIUM',
      'Redshift cluster does not have user activity logging enabled',
      ['aws_redshift_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const issues: string[] = [];

    const hasAuditLogging = this.hasAuditLoggingEnabled(resource);
    const paramGroupCompliance = this.checkParameterGroupCompliance(resource, allResources);

    if (!hasAuditLogging) {
      issues.push('enable database audit logging (via logging block with enable = true)');
    }

    if (paramGroupCompliance.hasIssue) {
      issues.push(paramGroupCompliance.issue!);
    }

    if (issues.length > 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `${issues.join(' and ')}.`
      );
    }

    return null;
  }

  private hasAuditLoggingEnabled(resource: TerraformResource): boolean {
    const logging = resource.values?.logging;
    return logging?.enable === true && !!logging?.bucket_name;
  }

  private checkParameterGroupCompliance(resource: TerraformResource, allResources: TerraformResource[]): { hasIssue: boolean; issue?: string } {
    const paramGroupName = resource.values?.cluster_parameter_group_name;

    if (!paramGroupName) {
      return {
        hasIssue: true,
        issue: "specify a cluster_parameter_group_name with 'enable_user_activity_logging' set to true"
      };
    }

    if (typeof paramGroupName === 'string' && paramGroupName.toLowerCase().includes('default')) {
      return {
        hasIssue: true,
        issue: 'use a non-default parameter group (default parameter groups cannot be modified)'
      };
    }

    const paramGroup = allResources.find(
      r => r.type === 'aws_redshift_parameter_group' &&
        (r.values?.name === paramGroupName || r.address === paramGroupName)
    );

    if (paramGroup) {
      const parameters = paramGroup.values?.parameter;
      if (!parameters || !Array.isArray(parameters)) {
        return {
          hasIssue: true,
          issue: `set 'enable_user_activity_logging' to true in parameter group '${paramGroupName}'`
        };
      }

      const userActivityParam = parameters.find(
        (param: any) => param.name === 'enable_user_activity_logging'
      );

      if (!userActivityParam) {
        return {
          hasIssue: true,
          issue: `set 'enable_user_activity_logging' to true in parameter group '${paramGroupName}'`
        };
      }

      const paramValue = userActivityParam.value;
      if (paramValue !== true && paramValue !== 'true' && paramValue !== '1') {
        return {
          hasIssue: true,
          issue: `set 'enable_user_activity_logging' to true in parameter group '${paramGroupName}'`
        };
      }

      return { hasIssue: false };
    }

    return {
      hasIssue: true,
      issue: `ensure parameter group '${paramGroupName}' has 'enable_user_activity_logging' set to true`
    };
  }
}

export default new TfRedshift006Rule();
