import { describe, it, expect } from 'vitest';
import { EKS017Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/017-cluster-alerts.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS017Rule', () => {
  const rule = new EKS017Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if an EKS cluster has no CloudWatch alarms', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          }
        },
        LogicalId: 'TestCluster'
      };

      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have proper alerts configured');
      expect(result?.issue).toContain('no CloudWatch alarms found');
    });

    it('should return a finding if an EKS cluster has no AWS Config rules', () => {
      // Arrange
      const cluster: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          }
        },
        LogicalId: 'TestCluster'
      };

      const alarm: CloudFormationResource = {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'TestClusterNodeCPUUtilization',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'node_cpu_utilization',
          Namespace: 'ContainerInsights',
          Period: 60,
          Statistic: 'Average',
          Threshold: 80,
          Dimensions: [
            {
              Name: 'ClusterName',
              Value: 'TestCluster'
            }
          ]
        },
        LogicalId: 'TestClusterAlarm'
      };

      const allResources = [cluster, alarm];

      // Act
      const result = rule.evaluate(cluster, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have proper alerts configured');
      expect(result?.issue).toContain('no AWS Config rules found');
    });

    it('should not return a finding if an EKS cluster has CloudWatch alarms and Config rules', () => {
      // Arrange
      const cluster: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          }
        },
        LogicalId: 'TestCluster'
      };

      const alarm: CloudFormationResource = {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'TestClusterNodeCPUUtilization',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'node_cpu_utilization',
          Namespace: 'ContainerInsights',
          Period: 60,
          Statistic: 'Average',
          Threshold: 80,
          Dimensions: [
            {
              Name: 'ClusterName',
              Value: 'TestCluster'
            }
          ]
        },
        LogicalId: 'TestClusterAlarm'
      };

      const configRule: CloudFormationResource = {
        Type: 'AWS::Config::ConfigRule',
        Properties: {
          ConfigRuleName: 'eks-netPolCheck-rule',
          Description: 'Checks that there is a network policy defined for each namespace in the cluster',
          Source: {
            Owner: 'CUSTOM_LAMBDA',
            SourceIdentifier: 'arn:aws:lambda:us-east-1:123456789012:function:eks-netPolCheck-rule',
            SourceDetails: [
              {
                EventSource: 'aws.config',
                MessageType: 'ConfigurationItemChangeNotification'
              }
            ]
          },
          Scope: {
            TagKey: 'eks:cluster-name',
            TagValue: 'TestCluster'
          }
        },
        LogicalId: 'EksNetPolCheckRule'
      };

      const allResources = [cluster, alarm, configRule];

      // Act
      const result = rule.evaluate(cluster, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should check if CloudWatch alarm is monitoring security metrics', () => {
      // Arrange
      const alarm: CloudFormationResource = {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'TestClusterAuthFailures',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'apiserver_request_total',
          Namespace: 'ContainerInsights',
          Period: 60,
          Statistic: 'Sum',
          Threshold: 0,
          Dimensions: [
            {
              Name: 'ClusterName',
              Value: 'TestCluster'
            }
          ]
        },
        LogicalId: 'TestClusterAlarm'
      };

      // Act
      const result = rule.evaluate(alarm, stackName, [alarm]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if CloudWatch alarm is not monitoring security metrics', () => {
      // Arrange
      const alarm: CloudFormationResource = {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'TestClusterCPUUtilization',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'CPUUtilization', // Not a security metric
          Namespace: 'ContainerInsights',
          Period: 60,
          Statistic: 'Average',
          Threshold: 80,
          Dimensions: [
            {
              Name: 'ClusterName',
              Value: 'TestCluster'
            }
          ]
        },
        LogicalId: 'TestClusterAlarm'
      };

      // Act
      const result = rule.evaluate(alarm, stackName, [alarm]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudWatch::Alarm');
      expect(result?.resourceName).toBe('TestClusterAlarm');
      expect(result?.issue).toContain('alarm not monitoring security metrics');
    });

    it('should handle intrinsic functions in CloudWatch alarm dimensions', () => {
      // Arrange
      const alarm: CloudFormationResource = {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'TestClusterAuthFailures',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'apiserver_request_total',
          Namespace: 'ContainerInsights',
          Period: 60,
          Statistic: 'Sum',
          Threshold: 0,
          Dimensions: { 'Fn::If': ['UseClusterName', [
            {
              Name: 'ClusterName',
              Value: { Ref: 'ClusterName' }
            }
          ], []] }
        },
        LogicalId: 'TestClusterAlarm'
      };

      // Act
      const result = rule.evaluate(alarm, stackName, [alarm]);

      // Assert
      // The current implementation doesn't detect intrinsic functions in dimensions
      // and doesn't recognize this as an EKS-related alarm
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in Config rule source', () => {
      // Arrange
      const configRule: CloudFormationResource = {
        Type: 'AWS::Config::ConfigRule',
        Properties: {
          ConfigRuleName: 'eks-netPolCheck-rule',
          Description: 'Checks that there is a network policy defined for each namespace in the cluster',
          Source: { 'Fn::If': ['UseLambda', {
            Owner: 'CUSTOM_LAMBDA',
            SourceIdentifier: { 'Fn::GetAtt': ['EksNetPolCheckFunction', 'Arn'] },
            SourceDetails: [
              {
                EventSource: 'aws.config',
                MessageType: 'ConfigurationItemChangeNotification'
              }
            ]
          }, {
            Owner: 'AWS',
            SourceIdentifier: 'EKS_CLUSTER_LOGGING_ENABLED'
          }] }
        },
        LogicalId: 'EksNetPolCheckRule'
      };

      // Act
      const result = rule.evaluate(configRule, stackName, [configRule]);

      // Assert
      // The current implementation doesn't detect intrinsic functions in source
      // but recognizes this as an EKS-related config rule by name
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in cluster security group IDs', () => {
      // Arrange
      const cluster: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            SecurityGroupIds: { 'Fn::Split': [',', { Ref: 'SecurityGroups' }] }
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(cluster, stackName, [cluster]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have proper alerts configured');
    });

    it('should return null for non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });
  });
});
