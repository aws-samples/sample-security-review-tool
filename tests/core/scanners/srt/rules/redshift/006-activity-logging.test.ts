import { describe, it, expect } from 'vitest';
import { Redshift006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/006-activity-logging.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift006Rule', () => {
  const rule = new Redshift006Rule();
  const stackName = 'test-stack';

  // Helper function to create RedShift ClusterParameterGroup test resources
  function createParameterGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    // Convert Parameters object to array format if provided
    let parameters: Array<{ParameterName: string, ParameterValue: any}> = [];
    if (props.Parameters) {
      if (Array.isArray(props.Parameters)) {
        parameters = props.Parameters;
      } else {
        parameters = Object.entries(props.Parameters).map(([key, value]) => ({
          ParameterName: key,
          ParameterValue: value
        }));
      }
    }
    
    const { Parameters, ...restProps } = props;
    
    return {
      Type: 'AWS::Redshift::ClusterParameterGroup',
      Properties: {
        Description: 'Test parameter group',
        ParameterGroupFamily: 'redshift-1.0',
        Parameters: parameters,
        ...restProps
      },
      LogicalId: props.LogicalId || 'TestParameterGroup'
    };
  }

  // Helper function to create RedShift Cluster test resources
  function createClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Redshift::Cluster',
      Properties: {
        ClusterType: 'single-node',
        NodeType: 'dc2.large',
        MasterUsername: 'admin',
        MasterUserPassword: 'Password123',
        ...props
      },
      LogicalId: props.LogicalId || 'TestCluster'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('REDSHIFT-006');
    });

    it('should have MEDIUM priority', () => {
      expect(rule.priority).toBe('MEDIUM');
    });

    it('should apply to RedShift Cluster resources', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::Redshift::ClusterParameterGroup')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Valid Configuration Tests', () => {
    it('should pass when both audit logging and user activity logging are enabled', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when audit logging is enabled via AuditLogging property and user activity logging is enabled', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' },
        AuditLogging: true
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when user activity logging is enabled with string "true"', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': 'true'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when user activity logging is enabled with string "1"', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': '1'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when user activity logging is enabled with CloudFormation intrinsic function', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': { Ref: 'EnableUserActivityLogging' }
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Invalid Configuration Tests', () => {
    it('should fail when audit logging is missing', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' }
        // Missing LoggingProperties and AuditLogging
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('enable database audit logging');
    });

    it('should fail when parameter group is missing', () => {
      // Arrange
      const resource = createClusterResource({
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
        // Missing ClusterParameterGroupName
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('specify a non-default ClusterParameterGroupName');
    });

    it('should fail when using default parameter group', () => {
      // Arrange
      const resource = createClusterResource({
        ClusterParameterGroupName: 'default',
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('use a non-default parameter group');
    });

    it('should fail when parameter group does not have enable_user_activity_logging', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'NonCompliantParamGroup',
        Parameters: {
          'some_other_param': 'value'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'NonCompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('set \'enable_user_activity_logging\' to true');
    });

    it('should fail when parameter group has enable_user_activity_logging set to false', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'NonCompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': false
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'NonCompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('set \'enable_user_activity_logging\' to true');
    });

    it('should fail when parameter group has enable_user_activity_logging set to "false"', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'NonCompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': 'false'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'NonCompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('set \'enable_user_activity_logging\' to true');
    });

    it('should fail when parameter group has enable_user_activity_logging set to "0"', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'NonCompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': '0'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'NonCompliantParamGroup' },
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('set \'enable_user_activity_logging\' to true');
    });

    it('should fail when both audit logging and user activity logging are missing', () => {
      // Arrange
      const resource = createClusterResource({
        // Missing both LoggingProperties/AuditLogging and ClusterParameterGroupName
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('enable database audit logging');
    });

    it('should fail when external parameter group is referenced but audit logging is missing', () => {
      // Arrange
      const resource = createClusterResource({
        ClusterParameterGroupName: 'external-param-group'
        // Missing LoggingProperties and AuditLogging
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
      expect(result?.fix).toContain('enable database audit logging');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const resource = {
        Type: 'AWS::Redshift::Cluster',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Redshift cluster does not have user activity logging enabled');
    });

    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act & Assert
      // First check that the rule doesn't apply to this resource type
      expect(rule.appliesTo(resource.Type)).toBe(false);
      
      // Then check that evaluate returns null for non-applicable resources
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Helper Methods Tests', () => {
    it('should correctly identify if audit logging is enabled with hasAuditLoggingEnabled', () => {
      // Arrange
      const resourceWithAuditLogging = createClusterResource({
        AuditLogging: true
      });
      
      const resourceWithLoggingProperties = createClusterResource({
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const resourceWithoutAuditLogging = createClusterResource({
        // No audit logging properties
      });

      // Act & Assert
      expect((rule as any).hasAuditLoggingEnabled(resourceWithAuditLogging)).toBe(true);
      expect((rule as any).hasAuditLoggingEnabled(resourceWithLoggingProperties)).toBe(true);
      expect((rule as any).hasAuditLoggingEnabled(resourceWithoutAuditLogging)).toBe(false);
    });

    it('should correctly check parameter group compliance with checkParameterGroupCompliance', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'CompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const nonCompliantParamGroup = createParameterGroupResource({
        LogicalId: 'NonCompliantParamGroup',
        Parameters: {
          'enable_user_activity_logging': false
        }
      });
      
      const resourceWithCompliantParamGroup = createClusterResource({
        ClusterParameterGroupName: { Ref: 'CompliantParamGroup' }
      });
      
      const resourceWithNonCompliantParamGroup = createClusterResource({
        ClusterParameterGroupName: { Ref: 'NonCompliantParamGroup' }
      });
      
      const resourceWithDefaultParamGroup = createClusterResource({
        ClusterParameterGroupName: 'default'
      });
      
      const resourceWithoutParamGroup = createClusterResource({
        // No parameter group
      });
      
      const allResources = [resourceWithCompliantParamGroup, resourceWithNonCompliantParamGroup, 
                           resourceWithDefaultParamGroup, resourceWithoutParamGroup, 
                           paramGroup, nonCompliantParamGroup];

      // Act & Assert
      expect((rule as any).checkParameterGroupCompliance(resourceWithCompliantParamGroup, allResources).hasIssue).toBe(false);
      expect((rule as any).checkParameterGroupCompliance(resourceWithNonCompliantParamGroup, allResources).hasIssue).toBe(true);
      expect((rule as any).checkParameterGroupCompliance(resourceWithDefaultParamGroup, allResources).hasIssue).toBe(true);
      expect((rule as any).checkParameterGroupCompliance(resourceWithoutParamGroup, allResources).hasIssue).toBe(true);
    });

    it('should correctly check if user activity logging is enabled with isUserActivityLoggingEnabled', () => {
      // Arrange
      const compliantParamGroup = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const compliantParamGroupString = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': 'true'
        }
      });
      
      const compliantParamGroupOne = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': '1'
        }
      });
      
      const nonCompliantParamGroup = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': false
        }
      });
      
      const paramGroupWithoutSetting = createParameterGroupResource({
        Parameters: {
          'some_other_param': 'value'
        }
      });
      
      const paramGroupWithIntrinsicFunction = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': { Ref: 'EnableUserActivityLogging' }
        }
      });

      // Act & Assert
      expect((rule as any).isUserActivityLoggingEnabled(compliantParamGroup)).toBe(true);
      expect((rule as any).isUserActivityLoggingEnabled(compliantParamGroupString)).toBe(true);
      expect((rule as any).isUserActivityLoggingEnabled(compliantParamGroupOne)).toBe(true);
      expect((rule as any).isUserActivityLoggingEnabled(nonCompliantParamGroup)).toBe(false);
      expect((rule as any).isUserActivityLoggingEnabled(paramGroupWithoutSetting)).toBe(false);
      expect((rule as any).isUserActivityLoggingEnabled(paramGroupWithIntrinsicFunction)).toBe(true);
    });

    it('should correctly find parameter group by name with findParameterGroupByName', () => {
      // Arrange
      const paramGroup1 = createParameterGroupResource({
        LogicalId: 'ParamGroup1'
      });
      
      const paramGroup2 = createParameterGroupResource({
        LogicalId: 'ParamGroup2',
        ParameterGroupName: 'custom-param-group'
      });
      
      const resources = [paramGroup1, paramGroup2];

      // Act & Assert
      expect((rule as any).findParameterGroupByName('ParamGroup1', resources)).toBe(paramGroup1);
      expect((rule as any).findParameterGroupByName('custom-param-group', resources)).toBe(paramGroup2);
      expect((rule as any).findParameterGroupByName('non-existent', resources)).toBeNull();
    });

    it('should correctly extract resource ID with getResourceId', () => {
      // Act & Assert
      expect((rule as any).getResourceId('string-id')).toBe('string-id');
      expect((rule as any).getResourceId({ Ref: 'resource-id' })).toBe('resource-id');
      expect((rule as any).getResourceId(null)).toBeNull();
      expect((rule as any).getResourceId(undefined)).toBeNull();
      expect((rule as any).getResourceId({ SomeOtherProp: 'value' })).toBeNull();
    });
  });
});
