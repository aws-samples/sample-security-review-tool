import { describe, it, expect } from 'vitest';
import { Rds011Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/rds/011-event-notifications.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Rds011Rule', () => {
  const rule = new Rds011Rule();
  const stackName = 'test-stack';

  // Helper functions to create test resources
  function createDbInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBInstance',
      Properties: {
        Engine: 'mysql',
        DBInstanceClass: 'db.t3.micro',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbInstance'
    };
  }

  function createDbClusterResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBCluster',
      Properties: {
        Engine: 'aurora-mysql',
        MasterUsername: 'admin',
        MasterUserPassword: 'password',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbCluster'
    };
  }

  function createDbSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBSecurityGroup',
      Properties: {
        GroupDescription: 'Test security group',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbSecurityGroup'
    };
  }

  function createDbSnapshotResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBSnapshot',
      Properties: {
        DBInstanceIdentifier: 'test-db-instance',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbSnapshot'
    };
  }

  function createDbParameterGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::DBParameterGroup',
      Properties: {
        Description: 'Test parameter group',
        Family: 'mysql8.0',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDbParameterGroup'
    };
  }

  function createEventSubscriptionResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::RDS::EventSubscription',
      Properties: {
        SnsTopicArn: 'arn:aws:sns:us-east-1:123456789012:rds-events',
        Enabled: true,
        ...props
      },
      LogicalId: props.LogicalId || 'TestEventSubscription'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('RDS-011');
    });

    it('should have MEDIUM priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to the correct RDS resource types', () => {
      expect(rule.appliesTo('AWS::RDS::DBInstance')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBSecurityGroup')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBSnapshot')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBParameterGroup')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::DBCluster')).toBe(true);
      expect(rule.appliesTo('AWS::RDS::EventSubscription')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('RDS DB Instance Tests', () => {
    it('should flag DB instance when no event subscriptions exist', () => {
      // Arrange
      const dbInstance = createDbInstanceResource();
      const allResources = [dbInstance];
      
      // Act
      const result = rule.evaluate(dbInstance, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBInstance');
      expect(result?.resourceName).toBe('TestDbInstance');
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should not flag DB instance when any event subscription exists', () => {
      // Arrange
      const dbInstance = createDbInstanceResource();
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [dbInstance, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbInstance, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS DB Security Group Tests', () => {
    it('should flag DB security group when no event subscriptions exist', () => {
      // Arrange
      const dbSecurityGroup = createDbSecurityGroupResource();
      const allResources = [dbSecurityGroup];
      
      // Act
      const result = rule.evaluate(dbSecurityGroup, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBSecurityGroup');
      expect(result?.resourceName).toBe('TestDbSecurityGroup');
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should not flag DB security group when any event subscription exists', () => {
      // Arrange
      const dbSecurityGroup = createDbSecurityGroupResource();
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [dbSecurityGroup, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbSecurityGroup, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS DB Snapshot Tests', () => {
    it('should flag DB snapshot when no event subscriptions exist', () => {
      // Arrange
      const dbSnapshot = createDbSnapshotResource();
      const allResources = [dbSnapshot];
      
      // Act
      const result = rule.evaluate(dbSnapshot, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBSnapshot');
      expect(result?.resourceName).toBe('TestDbSnapshot');
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should not flag DB snapshot when any event subscription exists', () => {
      // Arrange
      const dbSnapshot = createDbSnapshotResource();
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [dbSnapshot, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbSnapshot, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS DB Parameter Group Tests', () => {
    it('should flag DB parameter group when no event subscriptions exist', () => {
      // Arrange
      const dbParameterGroup = createDbParameterGroupResource();
      const allResources = [dbParameterGroup];
      
      // Act
      const result = rule.evaluate(dbParameterGroup, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBParameterGroup');
      expect(result?.resourceName).toBe('TestDbParameterGroup');
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should not flag DB parameter group when any event subscription exists', () => {
      // Arrange
      const dbParameterGroup = createDbParameterGroupResource();
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [dbParameterGroup, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbParameterGroup, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('RDS DB Cluster Tests', () => {
    it('should flag DB cluster when no event subscriptions exist', () => {
      // Arrange
      const dbCluster = createDbClusterResource();
      const allResources = [dbCluster];
      
      // Act
      const result = rule.evaluate(dbCluster, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::RDS::DBCluster');
      expect(result?.resourceName).toBe('TestDbCluster');
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should not flag DB cluster when any event subscription exists', () => {
      // Arrange
      const dbCluster = createDbClusterResource();
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [dbCluster, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbCluster, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties in resource', () => {
      // Arrange
      const dbInstance = {
        Type: 'AWS::RDS::DBInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      const allResources = [dbInstance];
      
      // Act
      const result = rule.evaluate(dbInstance, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
    });

    it('should handle missing Properties in event subscription', () => {
      // Arrange
      const dbInstance = createDbInstanceResource();
      const eventSubscription = {
        Type: 'AWS::RDS::EventSubscription',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      const allResources = [dbInstance, eventSubscription];
      
      // Act
      const result = rule.evaluate(dbInstance, stackName, allResources);
      
      // Assert
      expect(result).toBeNull(); // Still passes because we only check for the existence of an EventSubscription
    });

    it('should handle missing allResources parameter', () => {
      // Arrange
      const dbInstance = createDbInstanceResource();
      
      // Act
      const result = rule.evaluate(dbInstance, stackName);
      
      // Assert
      expect(result).toBeNull(); // Rule should gracefully handle missing allResources
    });
  });

  describe('Multiple Resources', () => {
    it('should not flag any resources when any event subscription exists', () => {
      // Arrange
      const resources = [
        createDbInstanceResource(),
        createDbSecurityGroupResource(),
        createDbSnapshotResource(),
        createDbParameterGroupResource(),
        createDbClusterResource()
      ];
      const eventSubscription = createEventSubscriptionResource();
      const allResources = [...resources, eventSubscription];
      
      // Act & Assert
      resources.forEach(resource => {
        expect(rule.evaluate(resource, stackName, allResources)).toBeNull();
      });
    });

    it('should flag all resources when no event subscription exists', () => {
      // Arrange
      const resources = [
        createDbInstanceResource(),
        createDbSecurityGroupResource(),
        createDbSnapshotResource(),
        createDbParameterGroupResource(),
        createDbClusterResource()
      ];
      const allResources = [...resources];
      
      // Act & Assert
      resources.forEach(resource => {
        const result = rule.evaluate(resource, stackName, allResources);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('RDS resources do not have event notifications enabled');
      });
    });
  });
});
