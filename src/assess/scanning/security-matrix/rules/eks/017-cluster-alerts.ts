import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS17 Rule: Ensure that alerts are created for the EKS cluster.
 * 
 * Documentation: "Create an alarm to automatically alert you where there is an increase in 403 Forbidden 
 * and 401 Unauthorized responses, and then use attributes like host, sourceIPs, and k8s_user.username to find out 
 * where those requests are coming from. AWS Custom Config Rules for Kubernetes:
 * *eks-netPolCheck-rule* Checks that there is a network policy defined for each namespace in the cluster
 * *eks-privEscalation-rule* Checks that there are no pods running containers with the AllowPrivilege Escalation flag
 * *eks-trustedRegCheck-rule* Checks that container images are from trusted sources"
 */
export class EKS017Rule extends BaseRule {
  constructor() {
    super(
      'EKS-017',
      'HIGH',
      'EKS cluster does not have proper alerts configured',
      ['AWS::EKS::Cluster', 'AWS::CloudWatch::Alarm', 'AWS::CloudWatch::CompositeAlarm', 'AWS::Config::ConfigRule']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      const clusterName = resource.Properties?.Name || resource.LogicalId;

      // Check if there are CloudWatch alarms for this cluster
      const hasCloudWatchAlarms = this.hasCloudWatchAlarmsForCluster(clusterName, allResources);

      if (!hasCloudWatchAlarms) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no CloudWatch alarms found)`,
          `Create CloudWatch alarms to monitor for security events like 401/403 responses, high error rates, or suspicious API calls.`
        );
      }

      // Check if there are Config rules for this cluster
      const hasConfigRules = this.hasConfigRulesForCluster(clusterName, allResources);

      if (!hasConfigRules) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no AWS Config rules found)`,
          `Create AWS Config rules to monitor for security best practices like network policies, privilege escalation, and trusted image sources.`
        );
      }
    }

    // Check if this is a CloudWatch alarm that should be monitoring an EKS cluster
    if (resource.Type === 'AWS::CloudWatch::Alarm' || resource.Type === 'AWS::CloudWatch::CompositeAlarm') {
      const isEksRelatedAlarm = this.isEksRelatedAlarm(resource);

      if (isEksRelatedAlarm) {
        // Check if the alarm is monitoring important security metrics
        const isMonitoringSecurityMetrics = this.isMonitoringSecurityMetrics(resource);

        if (!isMonitoringSecurityMetrics) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (alarm not monitoring security metrics)`,
            `Configure the alarm to monitor security-related metrics like 401/403 responses, API server errors, or authentication failures.`
          );
        }
      }
    }

    // Check if this is a Config rule that should be monitoring an EKS cluster
    if (resource.Type === 'AWS::Config::ConfigRule') {
      const isEksRelatedConfigRule = this.isEksRelatedConfigRule(resource);

      if (isEksRelatedConfigRule) {
        // Check if the rule is checking important security configurations
        const isCheckingSecurityConfigurations = this.isCheckingSecurityConfigurations(resource);

        if (!isCheckingSecurityConfigurations) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (Config rule not checking security configurations)`,
            `Configure the rule to check for security best practices like network policies, privilege escalation, or trusted image sources.`
          );
        }
      }
    }

    return null;
  }

  private hasCloudWatchAlarmsForCluster(clusterName: string, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    return allResources.some(resource => {
      if (resource.Type === 'AWS::CloudWatch::Alarm') {
        const dimensions = resource.Properties?.Dimensions;

        if (dimensions && Array.isArray(dimensions)) {
          return dimensions.some(dimension =>
            (dimension.Name === 'ClusterName' && dimension.Value === clusterName) ||
            (dimension.Name === 'Cluster' && dimension.Value === clusterName)
          );
        }

        const metricName = resource.Properties?.MetricName;
        if (metricName && typeof metricName === 'string') {
          return metricName.includes('EKS') || metricName.includes('Kubernetes');
        }

        const namespace = resource.Properties?.Namespace;
        if (namespace && typeof namespace === 'string') {
          return namespace.includes('EKS') || namespace.includes('Kubernetes') || namespace.includes('ContainerInsights');
        }
      }

      return false;
    });
  }

  private hasConfigRulesForCluster(clusterName: string, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    return allResources.some(resource => {
      if (resource.Type === 'AWS::Config::ConfigRule') {
        const source = resource.Properties?.Source;

        if (source) {
          const sourceDetails = source.SourceDetails;

          if (sourceDetails && Array.isArray(sourceDetails)) {
            return sourceDetails.some(detail => {
              const messageType = detail.MessageType;
              return messageType === 'ConfigurationItemChangeNotification' || messageType === 'OversizedConfigurationItemChangeNotification';
            });
          }

          const owner = source.Owner;
          if (owner === 'CUSTOM_LAMBDA') {
            const sourceIdentifier = source.SourceIdentifier;

            if (sourceIdentifier && typeof sourceIdentifier === 'string') {
              return sourceIdentifier.includes('eks') || sourceIdentifier.includes('kubernetes');
            }
          }
        }

        const scope = resource.Properties?.Scope;
        if (scope) {
          const tagKey = scope.TagKey;
          const tagValue = scope.TagValue;

          if (tagKey === 'eks:cluster-name' && tagValue === clusterName) {
            return true;
          }
        }
      }

      return false;
    });
  }

  private isEksRelatedAlarm(resource: CloudFormationResource): boolean {
    // Check dimensions for EKS-related dimensions
    const dimensions = resource.Properties?.Dimensions;
    if (dimensions && Array.isArray(dimensions)) {
      for (const dimension of dimensions) {
        if (
          dimension.Name === 'ClusterName' ||
          dimension.Name === 'Cluster' ||
          dimension.Name === 'Service' && dimension.Value === 'eks'
        ) {
          return true;
        }
      }
    }

    // Check metric name for EKS indicators
    const metricName = resource.Properties?.MetricName;
    if (metricName && typeof metricName === 'string') {
      if (
        metricName.includes('EKS') ||
        metricName.includes('Kubernetes') ||
        metricName.includes('K8s') ||
        metricName.includes('Cluster')
      ) {
        return true;
      }
    }

    // Check namespace for EKS indicators
    const namespace = resource.Properties?.Namespace;
    if (namespace && typeof namespace === 'string') {
      if (
        namespace.includes('EKS') ||
        namespace.includes('Kubernetes') ||
        namespace.includes('ContainerInsights')
      ) {
        return true;
      }
    }

    // Check alarm name for EKS indicators
    const alarmName = resource.Properties?.AlarmName || resource.LogicalId;
    if (alarmName && typeof alarmName === 'string') {
      if (
        alarmName.toLowerCase().includes('eks') ||
        alarmName.toLowerCase().includes('kubernetes') ||
        alarmName.toLowerCase().includes('k8s') ||
        alarmName.toLowerCase().includes('cluster')
      ) {
        return true;
      }
    }

    return false;
  }

  private isMonitoringSecurityMetrics(resource: CloudFormationResource): boolean {
    // Check metric name for security-related metrics
    const metricName = resource.Properties?.MetricName;
    if (metricName && typeof metricName === 'string') {
      const securityMetrics = [
        'HTTPCode_ELB_4XX', 'HTTPCode_ELB_5XX',
        'HTTPCode_Target_4XX', 'HTTPCode_Target_5XX',
        'RejectedConnectionCount', 'AuthenticationFailures',
        'AuthorizationFailures', 'UnauthorizedAttempts',
        '401Count', '403Count', 'ErrorCount',
        'cluster_failed_node', 'apiserver_request_total',
        'apiserver_request_count', 'apiserver_request_error'
      ];

      for (const securityMetric of securityMetrics) {
        if (metricName.includes(securityMetric)) {
          return true;
        }
      }
    }

    // Check alarm description for security-related keywords
    const alarmDescription = resource.Properties?.AlarmDescription;
    if (alarmDescription && typeof alarmDescription === 'string') {
      const securityKeywords = [
        'security', 'unauthorized', 'forbidden',
        'authentication', 'authorization', 'error',
        '401', '403', 'failed', 'failure',
        'attack', 'breach', 'compromise'
      ];

      for (const keyword of securityKeywords) {
        if (alarmDescription.toLowerCase().includes(keyword)) {
          return true;
        }
      }
    }

    // Check alarm name for security-related keywords
    const alarmName = resource.Properties?.AlarmName || resource.LogicalId;
    if (alarmName && typeof alarmName === 'string') {
      const securityKeywords = [
        'security', 'unauthorized', 'forbidden',
        'authentication', 'authorization', 'error',
        '401', '403', 'failed', 'failure',
        'attack', 'breach', 'compromise'
      ];

      for (const keyword of securityKeywords) {
        if (alarmName.toLowerCase().includes(keyword)) {
          return true;
        }
      }
    }

    return false;
  }

  private isEksRelatedConfigRule(resource: CloudFormationResource): boolean {
    // Check rule name for EKS indicators
    const configRuleName = resource.Properties?.ConfigRuleName || resource.LogicalId;
    if (configRuleName && typeof configRuleName === 'string') {
      if (
        configRuleName.includes('eks') ||
        configRuleName.includes('kubernetes') ||
        configRuleName.includes('k8s') ||
        configRuleName.includes('cluster')
      ) {
        return true;
      }
    }

    // Check source identifier for EKS indicators
    const source = resource.Properties?.Source;
    if (source) {
      const sourceIdentifier = source.SourceIdentifier;

      if (sourceIdentifier && typeof sourceIdentifier === 'string') {
        if (
          sourceIdentifier.includes('eks') ||
          sourceIdentifier.includes('kubernetes') ||
          sourceIdentifier.includes('k8s')
        ) {
          return true;
        }
      }
    }

    // Check scope for EKS indicators
    const scope = resource.Properties?.Scope;
    if (scope) {
      const tagKey = scope.TagKey;

      if (tagKey === 'eks:cluster-name' || tagKey === 'kubernetes.io/cluster/') {
        return true;
      }
    }

    return false;
  }

  private isCheckingSecurityConfigurations(resource: CloudFormationResource): boolean {
    // Check rule name for security-related keywords
    const configRuleName = resource.Properties?.ConfigRuleName || resource.LogicalId;
    if (configRuleName && typeof configRuleName === 'string') {
      const securityKeywords = [
        'security', 'network-policy', 'netpol',
        'privilege', 'escalation', 'trusted',
        'registry', 'image', 'source',
        'encryption', 'secret', 'rbac',
        'role', 'access', 'control'
      ];

      for (const keyword of securityKeywords) {
        if (configRuleName.toLowerCase().includes(keyword)) {
          return true;
        }
      }

      // Check for specific rule names mentioned in the documentation
      if (
        configRuleName.includes('eks-netPolCheck-rule') ||
        configRuleName.includes('eks-privEscalation-rule') ||
        configRuleName.includes('eks-trustedRegCheck-rule')
      ) {
        return true;
      }
    }

    // Check description for security-related keywords
    const description = resource.Properties?.Description;
    if (description && typeof description === 'string') {
      const securityKeywords = [
        'security', 'network policy', 'netpol',
        'privilege', 'escalation', 'trusted',
        'registry', 'image', 'source',
        'encryption', 'secret', 'rbac',
        'role', 'access', 'control'
      ];

      for (const keyword of securityKeywords) {
        if (description.toLowerCase().includes(keyword)) {
          return true;
        }
      }
    }

    return false;
  }
}

export default new EKS017Rule();
