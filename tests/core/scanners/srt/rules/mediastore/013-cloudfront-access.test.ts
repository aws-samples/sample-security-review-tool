import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIASTORE013Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediastore/013-cloudfront-access.js';

describe('MEDIASTORE013Rule', () => {
  let rule: MEDIASTORE013Rule;

  beforeEach(() => {
    rule = new MEDIASTORE013Rule();
  });

  it('should flag MediaStore container without Policy', () => {
    const resource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'TestContainer',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaStore container must have resource policy to restrict CloudFront access');
  });

  it('should flag MediaStore container with policy missing CloudFront configuration', () => {
    const resource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'TestContainer',
      Properties: {
        Policy: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Principal: '*',
            Action: 'mediastore:GetObject'
          }]
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaStore container must have resource policy to restrict CloudFront access');
  });

  it('should pass MediaStore container with CloudFront policy', () => {
    const resource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'TestContainer',
      Properties: {
        Policy: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'cloudfront.amazonaws.com' },
            Action: 'mediastore:GetObject',
            Condition: {
              StringEquals: {
                'AWS:SourceArn': 'arn:aws:cloudfront::*:distribution/*'
              }
            }
          }]
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should ignore non-MediaStore resources', () => {
    const resource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});