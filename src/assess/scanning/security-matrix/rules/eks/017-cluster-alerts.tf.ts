import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks017Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-017',
      'HIGH',
      'EKS cluster does not have proper alerts configured',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const clusterName = resource.values?.name || resource.name;

    const hasCloudWatchAlarms = allResources.some(r => {
      if (r.type !== 'aws_cloudwatch_metric_alarm') return false;

      const dimensions = r.values?.dimensions;
      if (dimensions && typeof dimensions === 'object') {
        if (dimensions.ClusterName === clusterName || dimensions.Cluster === clusterName) {
          return true;
        }
      }

      const namespace = r.values?.namespace;
      if (typeof namespace === 'string') {
        return namespace.includes('EKS') || namespace.includes('ContainerInsights');
      }

      return false;
    });

    if (!hasCloudWatchAlarms) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (no CloudWatch alarms found)`,
        'Create CloudWatch alarms to monitor for security events like 401/403 responses, high error rates, or suspicious API calls.'
      );
    }

    return null;
  }
}

export default new TfEks017Rule();
