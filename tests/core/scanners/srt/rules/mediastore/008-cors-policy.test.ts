import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIASTORE008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediastore/008-cors-policy.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('008-cors-policy: MediaStore CORS Policy Implementation', () => {
  let rule: MEDIASTORE008Rule;

  beforeEach(() => {
    rule = new MEDIASTORE008Rule();
  });

  it('should pass when MediaStore container has CORS policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'MyMediaStoreContainer',
      Properties: {
        ContainerName: 'my-container',
        CorsPolicy: [
          {
            AllowedOrigins: ['https://example.com'],
            AllowedMethods: ['GET', 'HEAD'],
            AllowedHeaders: ['*'],
            MaxAgeSeconds: 3000
          }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when MediaStore container lacks CORS policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'MyMediaStoreContainer',
      Properties: {
        ContainerName: 'my-container'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaStore container must implement CORS policy to explicitly allow/restrict access');
    expect(result?.fix).toContain('CorsPolicy');
  });

  it('should handle template without resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});