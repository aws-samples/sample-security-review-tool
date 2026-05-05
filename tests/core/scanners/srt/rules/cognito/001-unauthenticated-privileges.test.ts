import { describe, it, expect } from 'vitest';
import { Cognito001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cognito/001-unauthenticated-privileges.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Cognito001Rule', () => {
  const rule = new Cognito001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if AllowUnauthenticatedIdentities is false', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::IdentityPool',
        Properties: {
          IdentityPoolName: 'test-identity-pool',
          AllowUnauthenticatedIdentities: false
        },
        LogicalId: 'TestIdentityPool'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if AllowUnauthenticatedIdentities is true', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::IdentityPool',
        Properties: {
          IdentityPoolName: 'test-identity-pool',
          AllowUnauthenticatedIdentities: true
        },
        LogicalId: 'TestIdentityPool'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Cognito::IdentityPool');
      expect(result?.resourceName).toBe('TestIdentityPool');
      expect(result?.issue).toContain('Cognito Identity Pool allows unauthenticated users');
      expect(result?.fix).toContain('Set AllowUnauthenticatedIdentities to \'false\'');
    });

    it('should return a finding if AllowUnauthenticatedIdentities is an intrinsic function', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::IdentityPool',
        Properties: {
          IdentityPoolName: 'test-identity-pool',
          AllowUnauthenticatedIdentities: { Ref: 'AllowUnauthenticatedParameter' }
        },
        LogicalId: 'TestIdentityPool'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Cognito::IdentityPool');
      expect(result?.resourceName).toBe('TestIdentityPool');
      expect(result?.issue).toContain('Cognito Identity Pool allows unauthenticated users');
      expect(result?.fix).toContain('Set AllowUnauthenticatedIdentities to \'false\'');
    });

    it('should return a finding if AllowUnauthenticatedIdentities is not defined', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::IdentityPool',
        Properties: {
          IdentityPoolName: 'test-identity-pool'
          // AllowUnauthenticatedIdentities is not defined
        },
        LogicalId: 'TestIdentityPool'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Cognito::IdentityPool');
      expect(result?.resourceName).toBe('TestIdentityPool');
      expect(result?.issue).toContain('Cognito Identity Pool allows unauthenticated users');
      expect(result?.fix).toContain('Set AllowUnauthenticatedIdentities to \'false\'');
    });

    it('should return null for non-Cognito Identity Pool resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::UserPool',
        Properties: {
          UserPoolName: 'test-user-pool'
        },
        LogicalId: 'TestUserPool'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle multiple resources correctly', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Cognito::IdentityPool',
        Properties: {
          IdentityPoolName: 'test-identity-pool',
          AllowUnauthenticatedIdentities: false
        },
        LogicalId: 'TestIdentityPool'
      };

      const allResources: CloudFormationResource[] = [
        resource,
        {
          Type: 'AWS::Cognito::UserPool',
          Properties: {
            UserPoolName: 'test-user-pool'
          },
          LogicalId: 'TestUserPool'
        }
      ];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });
});
