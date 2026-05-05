import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIAPACKAGE007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediapackage/007-key-rotation-interval.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('007-key-rotation-interval: MediaPackage Key Rotation Interval', () => {
  let rule: MEDIAPACKAGE007Rule;

  beforeEach(() => {
    rule = new MEDIAPACKAGE007Rule();
  });

  it('should pass when key rotation interval is 300 seconds or more', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        HlsPackage: {
          Encryption: {
            KeyRotationIntervalSeconds: 300,
            SpekeKeyProvider: {
              ResourceId: 'string',
              RoleArn: 'arn:aws:iam::account:role/MediaPackageSpekeRole',
              SystemIds: ['string'],
              Url: 'https://speke.example.com'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when key rotation interval is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        HlsPackage: {
          Encryption: {
            SpekeKeyProvider: {
              ResourceId: 'string',
              RoleArn: 'arn:aws:iam::account:role/MediaPackageSpekeRole',
              SystemIds: ['string'],
              Url: 'https://speke.example.com'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaPackage origin endpoint with encryption must specify KeyRotationIntervalSeconds of at least 300');
    expect(result?.fix).toContain('KeyRotationIntervalSeconds');
  });

  it('should fail when key rotation interval is below 300 seconds', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        DashPackage: {
          Encryption: {
            KeyRotationIntervalSeconds: 120,
            SpekeKeyProvider: {
              ResourceId: 'string',
              RoleArn: 'arn:aws:iam::account:role/MediaPackageSpekeRole',
              SystemIds: ['string'],
              Url: 'https://speke.example.com'
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaPackage origin endpoint with encryption must specify KeyRotationIntervalSeconds of at least 300');
    expect(result?.fix).toContain('KeyRotationIntervalSeconds');
  });
});