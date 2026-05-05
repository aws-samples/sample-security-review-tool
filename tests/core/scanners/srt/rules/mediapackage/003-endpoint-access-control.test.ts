import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIAPACKAGE003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/mediapackage/003-endpoint-access-control.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('003-endpoint-access-control: MediaPackage Origin Endpoint Access Control', () => {
  let rule: MEDIAPACKAGE003Rule;

  beforeEach(() => {
    rule = new MEDIAPACKAGE003Rule();
  });

  it('should pass when origin endpoint has CDN authorization', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        Authorization: {
          CdnIdentifierSecret: 'arn:aws:secretsmanager:region:account:secret:secret-name',
          SecretsRoleArn: 'arn:aws:iam::account:role/MediaPackageSecretsRole'
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when origin endpoint has IP whitelist', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        Whitelist: ['192.168.1.0/24', '10.0.0.0/16']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when origin endpoint has no access control', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaPackage origin endpoint must restrict access using CDN authorization or IP whitelisting');
    expect(result?.fix).toContain('Authorization');
  });

  it('should fail when whitelist includes 0.0.0.0/0', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaPackage::OriginEndpoint',
      LogicalId: 'MyOriginEndpoint',
      Properties: {
        ChannelId: 'my-channel',
        Id: 'my-endpoint',
        Whitelist: ['0.0.0.0/0']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaPackage origin endpoint must restrict access using CDN authorization or IP whitelisting');
    expect(result?.fix).toContain('0.0.0.0/0');
  });
});