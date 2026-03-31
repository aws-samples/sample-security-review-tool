import { describe, it, expect } from 'vitest';
import { IdC006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iam-identity-center/006-permission-set-least-privilege.js';

describe('IdC-006: Assign IAM permission sets according to the principle of least privilege', () => {
  const rule = new IdC006Rule();

  it('should flag permission set with excessive session duration', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {
        SessionDuration: 'PT12H'
      }
    };
    const template = { Resources: { TestPermissionSet: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Set SessionDuration to PT8H');
  });

  it('should flag permission set with dangerous managed policies', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {
        SessionDuration: 'PT4H',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AdministratorAccess',
          'arn:aws:iam::aws:policy/PowerUserAccess'
        ]
      }
    };
    const template = { Resources: { TestPermissionSet: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Replace overly broad managed policies');
  });

  it('should flag permission set with wildcard inline policy', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {
        SessionDuration: 'PT4H',
        InlinePolicy: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: '*',
              Resource: 'arn:aws:s3:::my-bucket/*'
            }]
          }
        }
      }
    };
    const template = { Resources: { TestPermissionSet: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Replace wildcard permissions (*) with specific actions');
  });

  it('should pass compliant permission set', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {
        SessionDuration: 'PT4H',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/ReadOnlyAccess'
        ],
        InlinePolicy: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::my-bucket/*'
            }]
          }
        }
      }
    };
    const template = { Resources: { TestPermissionSet: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).toBeNull();
  });

  it('should flag permission set without session duration', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {}
    };
    const template = { Resources: { TestPermissionSet: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Set SessionDuration to PT8H');
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
    expect(rule.id).toBe('IdC-006');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::SSO::PermissionSet')).toBe(true);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });

  it('should return null for evaluate method', () => {
    const resource = {
      Type: 'AWS::SSO::PermissionSet',
      Properties: {},
      LogicalId: 'TestPermissionSet'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });
});