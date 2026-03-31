import { describe, it, expect } from 'vitest';
import { SL001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/security-lake/001-subscriber-least-privilege.js';

describe('SL-001: Restrict AWS Security Lake subscriber permissions according to least privilege', () => {
  const rule = new SL001Rule();

  it('should flag wildcard in Principal', () => {
    const resource = {
      Type: 'AWS::SecurityLake::Subscriber',
      Properties: {
        Sources: [{ AwsLogSource: { SourceName: 'CLOUDTRAIL_MGMT' } }],
        SubscriberIdentity: {
          Principal: '*',
          ExternalId: 'test-id'
        }
      }
    };
    const template = { Resources: { TestSubscriber: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Replace wildcard Principal "*"');
  });

  it('should flag exceeding AWS maximum sources (>10)', () => {
    const resource = {
      Type: 'AWS::SecurityLake::Subscriber',
      Properties: {
        Sources: Array.from({ length: 11 }, (_, i) => 
          ({ AwsLogSource: { SourceName: `SOURCE_${i}` } })
        ),
        SubscriberIdentity: {
          Principal: 'arn:aws:iam::123456789012:role/TestRole'
        }
      }
    };
    const template = { Resources: { TestSubscriber: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Reduce Sources array from 11 to maximum 10');
  });

  it('should pass compliant subscriber', () => {
    const resource = {
      Type: 'AWS::SecurityLake::Subscriber',
      Properties: {
        Sources: [{ AwsLogSource: { SourceName: 'CLOUDTRAIL_MGMT' } }],
        AccessTypes: ['LAKEFORMATION'],
        SubscriberIdentity: {
          Principal: 'lambda.amazonaws.com'
        }
      }
    };
    const template = { Resources: { TestSubscriber: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).toBeNull();
  });

  it('should ignore non-applicable resources', () => {
    const resource = {
      Type: 'AWS::S3::Bucket',
      Properties: {}
    };

    const result = rule.evaluateResource('TestStack', { Resources: {} }, resource);
    expect(result).toBeNull();
  });

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('SL-001');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::SecurityLake::Subscriber')).toBe(true);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });
});