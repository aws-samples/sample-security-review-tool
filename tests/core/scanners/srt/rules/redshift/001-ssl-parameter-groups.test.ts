import { describe, it, expect } from 'vitest';
import { Redshift001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/redshift/001-ssl-parameter-groups.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Redshift001Rule', () => {
  const rule = new Redshift001Rule();
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
      expect(rule.id).toBe('REDSHIFT-001');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to RedShift Cluster and ClusterParameterGroup resources', () => {
      expect(rule.appliesTo('AWS::Redshift::Cluster')).toBe(true);
      expect(rule.appliesTo('AWS::Redshift::ClusterParameterGroup')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Parameter Group Tests', () => {
    it('should pass when require_ssl is true', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': true
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when require_ssl is "true"', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': 'true'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when require_ssl is "1"', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': '1'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should fail when require_ssl is false', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': false
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('TestParameterGroup');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Set \'require_ssl\' parameter to \'true\'');
    });

    it('should fail when require_ssl is "false"', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': 'false'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('TestParameterGroup');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Set \'require_ssl\' parameter to \'true\'');
    });

    it('should fail when require_ssl is "0"', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': '0'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('TestParameterGroup');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Set \'require_ssl\' parameter to \'true\'');
    });

    it('should fail when require_ssl is missing', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'some_other_param': 'value'
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('TestParameterGroup');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Add \'require_ssl\' parameter with value \'true\'');
    });

    it('should fail when Parameters property is missing', () => {
      // Arrange
      const resource = createParameterGroupResource();
      delete resource.Properties.Parameters;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('TestParameterGroup');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Add \'require_ssl\' parameter with value \'true\'');
    });

    it('should pass when require_ssl uses CloudFormation intrinsic function', () => {
      // Arrange
      const resource = createParameterGroupResource({
        Parameters: {
          'require_ssl': { Ref: 'RequireSslParameter' }
        }
      });

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Cluster Tests', () => {
    it('should fail when ClusterParameterGroupName is missing', () => {
      // Arrange
      const resource = createClusterResource();

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
      expect(result?.fix).toContain('Specify a ClusterParameterGroupName with \'require_ssl\' set to \'true\' for explicit SSL configuration');
    });

    it('should pass when referenced parameter group is defined in the same template (skipped to avoid duplicates)', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'SSLEnabledParamGroup',
        Parameters: {
          'require_ssl': true
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'SSLEnabledParamGroup' }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when referenced parameter group has SSL disabled but is defined in the same template (skipped to avoid duplicates)', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'SSLDisabledParamGroup',
        Parameters: {
          'require_ssl': false
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'SSLDisabledParamGroup' }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when referenced parameter group is missing require_ssl but is defined in the same template (skipped to avoid duplicates)', () => {
      // Arrange
      const paramGroup = createParameterGroupResource({
        LogicalId: 'MissingSSLParamGroup',
        Parameters: {
          'some_other_param': 'value'
        }
      });
      
      const resource = createClusterResource({
        ClusterParameterGroupName: { Ref: 'MissingSSLParamGroup' }
      });
      
      const allResources = [resource, paramGroup];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should pass when parameter group is not found in template (assume external)', () => {
      // Arrange
      const resource = createClusterResource({
        ClusterParameterGroupName: 'external-param-group'
      });
      
      const allResources = [resource];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Arrange
      const resource = {
        Type: 'AWS::Redshift::ClusterParameterGroup',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Redshift::ClusterParameterGroup');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('RedShift cluster parameter group does not have SSL enabled');
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
});
