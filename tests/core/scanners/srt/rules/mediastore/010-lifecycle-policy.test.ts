import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIASTORE010Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediastore/010-lifecycle-policy.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('010-lifecycle-policy: MediaStore Object Lifecycle Policy', () => {
  let rule: MEDIASTORE010Rule;

  beforeEach(() => {
    rule = new MEDIASTORE010Rule();
  });

  it('should pass when MediaStore container has lifecycle policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'MyMediaStoreContainer',
      Properties: {
        ContainerName: 'my-container',
        LifecyclePolicy: '{"rules":[{"definition":{"path":[{"wildcard":"*"}],"days_since_create":[{"numeric":[">",30]}]},"action":"EXPIRE"}]}'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when MediaStore container lacks lifecycle policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaStore::Container',
      LogicalId: 'MyMediaStoreContainer',
      Properties: {
        ContainerName: 'my-container'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaStore container must implement object lifecycle policy to govern object storage duration');
    expect(result?.fix).toContain('LifecyclePolicy');
  });
});