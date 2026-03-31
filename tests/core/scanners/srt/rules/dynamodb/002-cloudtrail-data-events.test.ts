import { describe, it, expect } from 'vitest';
import { Ddb002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/002-cloudtrail-data-events.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Ddb002Rule', () => {
  const rule = new Ddb002Rule();
  const stackName = 'test-stack';

  // Helper functions to create test resources
  function createDynamoDBTableResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::DynamoDB::Table',
      Properties: {
        AttributeDefinitions: [
          {
            AttributeName: 'id',
            AttributeType: 'S'
          }
        ],
        KeySchema: [
          {
            AttributeName: 'id',
            KeyType: 'HASH'
          }
        ],
        BillingMode: 'PAY_PER_REQUEST',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDynamoDBTable'
    };
  }

  function createCloudTrailTrailResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::CloudTrail::Trail',
      Properties: {
        IsLogging: true,
        S3BucketName: 'test-bucket',
        ...props
      },
      LogicalId: props.LogicalId || 'TestCloudTrailTrail'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('DDB-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to the correct resource types', () => {
      expect(rule.appliesTo('AWS::DynamoDB::Table')).toBe(true);
      expect(rule.appliesTo('AWS::CloudTrail::Trail')).toBe(true);
      expect(rule.appliesTo('AWS::DynamoDB::GlobalTable')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DynamoDB Table Tests', () => {
    it('should detect missing CloudTrail trail', () => {
      // Arrange
      const table = createDynamoDBTableResource();
      const allResources = [table];
      
      // Act
      const result = rule.evaluate(table, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DynamoDB data plane events are not captured by CloudTrail logging');
    });

    it('should detect CloudTrail trail without DynamoDB data events', () => {
      // Arrange
      const table = createDynamoDBTableResource();
      const trail = createCloudTrailTrailResource({
        EventSelectors: [
          {
            ReadWriteType: 'All',
            IncludeManagementEvents: true,
            DataResources: [
              {
                Type: 'AWS::S3::Object',
                Values: ['arn:aws:s3:::*/*']
              }
            ]
          }
        ]
      });
      const allResources = [table, trail];
      
      // Act
      const result = rule.evaluate(table, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DynamoDB data plane events are not captured by CloudTrail logging');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      // Arrange
      const table = createDynamoDBTableResource();
      const trail = createCloudTrailTrailResource({
        EventSelectors: [
          {
            ReadWriteType: 'All',
            IncludeManagementEvents: true,
            DataResources: [
              {
                Type: 'AWS::DynamoDB::Table',
                Values: ['arn:aws:dynamodb:::*']
              }
            ]
          }
        ]
      });
      const allResources = [table, trail];
      
      // Act
      const result = rule.evaluate(table, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should pass with wildcard data resource values', () => {
      // Arrange
      const table = createDynamoDBTableResource();
      const trail = createCloudTrailTrailResource({
        EventSelectors: [
          {
            ReadWriteType: 'All',
            IncludeManagementEvents: true,
            DataResources: [
              {
                Type: 'AWS::DynamoDB::Table',
                Values: ['*']
              }
            ]
          }
        ]
      });
      const allResources = [table, trail];
      
      // Act
      const result = rule.evaluate(table, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });


  describe('Edge Cases', () => {
    it('should handle missing Properties in resource', () => {
      // Arrange
      const table = {
        Type: 'AWS::DynamoDB::Table',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      const allResources = [table];
      
      // Act
      const result = rule.evaluate(table, stackName, allResources);
      
      // Assert
      expect(result).toBeNull(); // Should gracefully handle missing properties
    });

    it('should handle missing allResources parameter', () => {
      // Arrange
      const table = createDynamoDBTableResource();
      
      // Act
      const result = rule.evaluate(table, stackName);
      
      // Assert
      expect(result).not.toBeNull(); // Should flag missing CloudTrail configuration
      expect(result?.issue).toContain('DynamoDB data plane events are not captured by CloudTrail logging');
    });

    it('should ignore non-DynamoDB resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull(); // Should ignore non-applicable resources
    });
  });
});
