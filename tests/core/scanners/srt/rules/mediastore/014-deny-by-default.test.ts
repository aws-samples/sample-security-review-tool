import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIASTORE014Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediastore/014-deny-by-default.cf.js';

describe('MEDIASTORE014Rule', () => {
  let rule: MEDIASTORE014Rule;

  beforeEach(() => {
    rule = new MEDIASTORE014Rule();
  });

  it('should flag MediaStore container without Policy', () => {
    const resource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'TestContainer',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaStore container must implement deny-by-default policy to prevent unintended access');
  });

  it('should flag MediaStore container without explicit deny statement', () => {
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
    expect(result?.issue).toContain('MediaStore container must implement deny-by-default policy to prevent unintended access');
  });

  it('should pass MediaStore container with deny-by-default policy', () => {
    const resource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'TestContainer',
      Properties: {
        Policy: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Deny',
            Principal: '*',
            Action: '*',
            Resource: '*',
            Condition: {
              Bool: {
                'aws:SecureTransport': 'false'
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