import { describe, it, expect } from 'vitest';
import { Ddb002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/002-cloudtrail-data-events.cf.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Ddb002Rule', () => {
  const rule = new Ddb002Rule();
  const stackName = 'test-stack';

  function createTemplate(tableProps: Record<string, any> = {}, trailProps?: Record<string, any>): Template {
    const resources: Record<string, any> = {
      TestDynamoDBTable: {
        Type: 'AWS::DynamoDB::Table',
        Properties: {
          AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
          KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
          BillingMode: 'PAY_PER_REQUEST',
          ...tableProps
        }
      }
    };

    if (trailProps) {
      resources.TestCloudTrailTrail = {
        Type: 'AWS::CloudTrail::Trail',
        Properties: { IsLogging: true, S3BucketName: 'test-bucket', ...trailProps }
      };
    }

    return { Resources: resources };
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
      expect(rule.appliesTo('AWS::DynamoDB::GlobalTable')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('DynamoDB Table Tests', () => {
    it('should detect missing CloudTrail trail', () => {
      const template = createTemplate();
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestDynamoDBTable'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DynamoDB data plane events are not captured by CloudTrail logging');
    });

    it('should detect CloudTrail trail without DynamoDB data events', () => {
      const template = createTemplate({}, {
        EventSelectors: [{
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [{ Type: 'AWS::S3::Object', Values: ['arn:aws:s3:::*/*'] }]
        }]
      });
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestDynamoDBTable'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.issue).toContain('DynamoDB data plane events are not captured by CloudTrail logging');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const template = createTemplate({}, {
        EventSelectors: [{
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [{ Type: 'AWS::DynamoDB::Table', Values: ['arn:aws:dynamodb:::*'] }]
        }]
      });
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestDynamoDBTable'] as Resource);

      expect(result).toBeNull();
    });

    it('should pass with wildcard data resource values', () => {
      const template = createTemplate({}, {
        EventSelectors: [{
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [{ Type: 'AWS::DynamoDB::Table', Values: ['*'] }]
        }]
      });
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestDynamoDBTable'] as Resource);

      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties in resource', () => {
      const template: Template = {
        Resources: {
          TestTable: { Type: 'AWS::DynamoDB::Table' } as any
        }
      };
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTable'] as Resource);

      expect(result).toBeNull();
    });

    it('should ignore non-DynamoDB resources', () => {
      const template: Template = {
        Resources: {
          TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'test-bucket' } }
        }
      };
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);

      expect(result).toBeNull();
    });
  });

  describe('evaluate (legacy stub)', () => {
    it('should return null', () => {
      const result = rule.evaluate(
        { Type: 'AWS::DynamoDB::Table', Properties: {}, LogicalId: 'Test' },
        stackName
      );
      expect(result).toBeNull();
    });
  });
});
