import { describe, it, expect } from 'vitest';
import { O001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/organizations/001-service-access-monitoring.cf.js';

describe('ORG-001: Enable AWS Organizations service access according to least-privilege', () => {
  const rule = new O001Rule();

  it('should return null for evaluate method', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {},
      LogicalId: 'TestFunction'
    };

    const result = rule.evaluate(resource, 'TestStack');
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

  it('should flag Organization with ALL features without SCPs', () => {
    const resource = {
      Type: 'AWS::Organizations::Organization',
      Properties: {
        FeatureSet: 'ALL'
      }
    };
    const template = { Resources: { TestOrg: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toBe('Add Service Control Policy with deny statements for organizations:EnableAWSServiceAccess and organizations:DisableAWSServiceAccess actions.');
  });

  it('should flag Organization with default FeatureSet (ALL) without SCPs', () => {
    const resource = {
      Type: 'AWS::Organizations::Organization',
      Properties: {}
    };
    const template = { Resources: { TestOrg: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toBe('Add Service Control Policy with deny statements for organizations:EnableAWSServiceAccess and organizations:DisableAWSServiceAccess actions.');
  });

  it('should pass Organization with CONSOLIDATED_BILLING', () => {
    const resource = {
      Type: 'AWS::Organizations::Organization',
      Properties: {
        FeatureSet: 'CONSOLIDATED_BILLING'
      }
    };
    const template = { Resources: { TestOrg: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).toBeNull();
  });

  it('should pass Organization with ALL features when proper SCPs exist', () => {
    const orgResource = {
      Type: 'AWS::Organizations::Organization',
      Properties: {
        FeatureSet: 'ALL'
      }
    };
    const scpResource = {
      Type: 'AWS::Organizations::Policy',
      Properties: {
        Type: 'SERVICE_CONTROL_POLICY',
        PolicyDocument: {
          Statement: [{
            Effect: 'Deny',
            Action: 'organizations:EnableAWSServiceAccess',
            Resource: '*'
          }]
        }
      }
    };
    const template = { Resources: { TestOrg: orgResource, TestSCP: scpResource } };

    const result = rule.evaluateResource('TestStack', template, orgResource);
    expect(result).toBeNull();
  });

  it('should flag SCP without proper service access restrictions', () => {
    const resource = {
      Type: 'AWS::Organizations::Policy',
      Properties: {
        Type: 'SERVICE_CONTROL_POLICY',
        PolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Action: '*',
            Resource: '*'
          }]
        }
      }
    };
    const template = { Resources: { TestSCP: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toBe('Add deny statements for organizations:EnableAWSServiceAccess and organizations:DisableAWSServiceAccess actions to Service Control Policy.');
  });

  it('should pass SCP with proper service access restrictions', () => {
    const resource = {
      Type: 'AWS::Organizations::Policy',
      Properties: {
        Type: 'SERVICE_CONTROL_POLICY',
        PolicyDocument: {
          Statement: [{
            Effect: 'Deny',
            Action: ['organizations:EnableAWSServiceAccess', 'organizations:DisableAWSServiceAccess'],
            Resource: '*'
          }]
        }
      }
    };
    const template = { Resources: { TestSCP: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).toBeNull();
  });

  it('should check rule applies to correct resource types', () => {
    expect(rule.appliesTo('AWS::Organizations::Organization')).toBe(true);
    expect(rule.appliesTo('AWS::Organizations::Policy')).toBe(true);
    expect(rule.appliesTo('AWS::Events::Rule')).toBe(false); // No longer checking EventBridge
    expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('ORG-001');
    expect(rule.priority).toBe('HIGH');
  });
});