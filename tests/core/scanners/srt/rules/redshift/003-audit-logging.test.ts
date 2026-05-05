import { describe, it, expect } from 'vitest';
import { Redshift003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/003-audit-logging.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift003Rule', () => {
  const rule = new Redshift003Rule();
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
      expect(rule.id).toBe('REDSHIFT-003');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RedShift Cluster resources', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::Redshift::ClusterParameterGroup')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  // describe('Parameter Group Tests', () => {
  //   it('should pass when evaluateParameterGroup is called with enable_user_activity_logging set to true', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': true
  //       }
  //     });

  //     // Act
  //     // We need to access the private method via any type casting
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).toBeNull();
  //   });

  //   it('should pass when evaluateParameterGroup is called with enable_user_activity_logging set to "true"', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': 'true'
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).toBeNull();
  //   });

  //   it('should pass when evaluateParameterGroup is called with enable_user_activity_logging set to "1"', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': '1'
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).toBeNull();
  //   });

  //   it('should fail when evaluateParameterGroup is called with enable_user_activity_logging set to false', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': false
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Set \'enable_user_activity_logging\' parameter to \'true\'');
  //   });

  //   it('should fail when evaluateParameterGroup is called with enable_user_activity_logging set to "false"', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': 'false'
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Set \'enable_user_activity_logging\' parameter to \'true\'');
  //   });

  //   it('should fail when evaluateParameterGroup is called with enable_user_activity_logging set to "0"', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': '0'
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Set \'enable_user_activity_logging\' parameter to \'true\'');
  //   });

  //   it('should fail when evaluateParameterGroup is called with enable_user_activity_logging missing', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'some_other_param': 'value'
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Add \'enable_user_activity_logging\' parameter with value \'true\'');
  //   });

  //   it('should fail when evaluateParameterGroup is called with Parameters property missing', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource();
  //     delete resource.Properties.Parameters;

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Add \'enable_user_activity_logging\' parameter with value \'true\'');
  //   });

  //   it('should fail when evaluateParameterGroup is called with enable_user_activity_logging using CloudFormation intrinsic function', () => {
  //     // Arrange
  //     const resource = createParameterGroupResource({
  //       Parameters: {
  //         'enable_user_activity_logging': { Ref: 'EnableAuditLoggingParameter' }
  //       }
  //     });

  //     // Act
  //     const result = (rule as any).evaluateParameterGroup(resource, stackName);

  //     // Assert
  //     expect(result).not.toBeNull();
  //     expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
  //     expect(result?.resourceName).toBe('TestParameterGroup');
  //     expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
  //     expect(result?.issue).toContain('Add \'enable_user_activity_logging\' parameter with value \'true\'');
  //   });
  // });

  describe('Cluster Tests', () => {
    it('should pass when AuditLogging is true and LoggingProperties with BucketName is provided', () => {
      // Arrange
      const resource = createClusterResource({
        AuditLogging: true,
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when AuditLogging is true but LoggingProperties is missing', () => {
      // Arrange
      const resource = createClusterResource({
        AuditLogging: true
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
      expect(result?.fix).toContain('Add LoggingProperties with BucketName to store audit logs');
    });

    it('should fail when AuditLogging is true but BucketName is missing', () => {
      // Arrange
      const resource = createClusterResource({
        AuditLogging: true,
        LoggingProperties: {}
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
      expect(result?.fix).toContain('Add LoggingProperties with BucketName to store audit logs');
    });

    it('should fail when ClusterParameterGroupName is missing', () => {
      // Arrange
      const resource = createClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
    });

    it('should pass when referenced parameter group is defined in the same template with audit logging enabled', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'AuditLoggingEnabledParamGroup',
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'AuditLoggingEnabledParamGroup' },
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

    it('should fail when referenced parameter group is defined in the same template with audit logging disabled', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'AuditLoggingDisabledParamGroup',
        Parameters: {
          'enable_user_activity_logging': false
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'AuditLoggingDisabledParamGroup' },
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
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
    });

    it('should fail when referenced parameter group is defined in the same template with audit logging missing', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'MissingAuditLoggingParamGroup',
        Parameters: {
          'some_other_param': 'value'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'MissingAuditLoggingParamGroup' },
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
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
    });

    it('should pass when referenced parameter group is not found in template but LoggingProperties exists', () => {
      // Arrange
      const resource = createClusterResource({
        ClusterParameterGroupName: 'external-param-group',
        LoggingProperties: {
          BucketName: 'audit-logs-bucket'
        }
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when referenced parameter group is not found in template and LoggingProperties does not exist', () => {
      // Arrange
      const resource = createClusterResource({
        ClusterParameterGroupName: 'external-param-group'
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
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
      expect(result?.issue).toContain('Redshift cluster does not have audit logging enabled');
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

  describe('Helper Methods', () => {
    it('should correctly identify parameter group compliance with isParameterGroupCompliant', () => {
      // Arrange
      const compliantGroup = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': true
        }
      });
      
      const nonCompliantGroup = createParameterGroupResource({
        Parameters: {
          'enable_user_activity_logging': false
        }
      });
      
      const missingParamGroup = createParameterGroupResource({
        Parameters: {
          'some_other_param': 'value'
        }
      });

      // Act & Assert
      expect((rule as any).isParameterGroupCompliant(compliantGroup)).toBe(true);
      expect((rule as any).isParameterGroupCompliant(nonCompliantGroup)).toBe(false);
      expect((rule as any).isParameterGroupCompliant(missingParamGroup)).toBe(false);
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
