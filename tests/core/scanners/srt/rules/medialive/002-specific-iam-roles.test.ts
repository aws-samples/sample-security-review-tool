import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIALIVE002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/medialive/002-specific-iam-roles.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('002-specific-iam-roles: MediaLive Specific IAM Roles', () => {
  let rule: MEDIALIVE002Rule;

  beforeEach(() => {
    rule = new MEDIALIVE002Rule();
  });

  it('should pass when each MediaLive channel has unique IAM role', () => {
    const channel1: CloudFormationResource = {
      Type: 'AWS::MediaLive::Channel',
      LogicalId: 'Channel1',
      Properties: {
        Name: 'channel-1',
        RoleArn: 'arn:aws:iam::account:role/MediaLive-Channel1-Role'
      }
    };

    const channel2: CloudFormationResource = {
      Type: 'AWS::MediaLive::Channel',
      LogicalId: 'Channel2',
      Properties: {
        Name: 'channel-2',
        RoleArn: 'arn:aws:iam::account:role/MediaLive-Channel2-Role'
      }
    };

    const result1 = rule.evaluate(channel1, 'test-stack', [channel1, channel2]);
    const result2 = rule.evaluate(channel2, 'test-stack', [channel1, channel2]);
    expect(result1).toBeNull();
    expect(result2).toBeNull();
  });

  it('should fail when MediaLive channel lacks IAM role', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaLive::Channel',
      LogicalId: 'Channel1',
      Properties: {
        Name: 'channel-1'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaLive channel must specify a dedicated IAM role');
    expect(result?.fix).toContain('RoleArn');
  });

  it('should fail when MediaLive channels share IAM role', () => {
    const channel1: CloudFormationResource = {
      Type: 'AWS::MediaLive::Channel',
      LogicalId: 'Channel1',
      Properties: {
        Name: 'channel-1',
        RoleArn: 'arn:aws:iam::account:role/SharedMediaLiveRole'
      }
    };

    const channel2: CloudFormationResource = {
      Type: 'AWS::MediaLive::Channel',
      LogicalId: 'Channel2',
      Properties: {
        Name: 'channel-2',
        RoleArn: 'arn:aws:iam::account:role/SharedMediaLiveRole'
      }
    };

    const result = rule.evaluate(channel2, 'test-stack', [channel1, channel2]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaLive channel is sharing an IAM role with another channel');
    expect(result?.fix).toContain('RoleArn');
  });
});