import { describe, it, expect, beforeEach } from 'vitest';
import { MEDIALIVE003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/medialive/003-security-group-restrictions.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('003-security-group-restrictions: MediaLive Input Security Group Restrictions', () => {
  let rule: MEDIALIVE003Rule;

  beforeEach(() => {
    rule = new MEDIALIVE003Rule();
  });

  it('should pass when input security group has specific whitelist rules', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaLive::InputSecurityGroup',
      LogicalId: 'MyInputSecurityGroup',
      Properties: {
        WhitelistRules: [
          { Cidr: '192.168.1.0/24' },
          { Cidr: '10.0.0.0/16' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when input security group has no whitelist rules', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaLive::InputSecurityGroup',
      LogicalId: 'MyInputSecurityGroup',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaLive input security group must have specific whitelist rules to restrict access');
    expect(result?.fix).toContain('WhitelistRules');
  });

  it('should fail when input security group allows unrestricted access', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MediaLive::InputSecurityGroup',
      LogicalId: 'MyInputSecurityGroup',
      Properties: {
        WhitelistRules: [
          { Cidr: '0.0.0.0/0' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('MediaLive input security group must have specific whitelist rules to restrict access');
    expect(result?.fix).toContain('0.0.0.0/0');
  });
});