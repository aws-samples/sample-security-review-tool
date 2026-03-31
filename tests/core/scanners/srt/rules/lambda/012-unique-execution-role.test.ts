import { describe, it, expect } from 'vitest';
import { CompLamb012Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/012-unique-execution-role.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb012Rule - Unique Execution Role Tests', () => {
  const rule = new CompLamb012Rule();
  const stackName = 'test-stack';

  // Helper function to create Lambda test resources
  function createLambdaResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Lambda::Function',
      Properties: {
        Handler: 'index.handler',
        Runtime: 'nodejs14.x',
        Code: {
          S3Bucket: 'my-bucket',
          S3Key: 'my-key'
        },
        Role: props.Role || 'arn:aws:iam::123456789012:role/lambda-role',
        ...props
      },
      LogicalId: props.LogicalId || 'TestFunction'
    };
  }

  // Helper function to create IAM Role test resources
  function createRoleResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'lambda.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        ],
        ...props
      },
      LogicalId: props.LogicalId || 'TestRole'
    };
  }

  describe('Unique Execution Roles', () => {
    it('should accept Lambda functions with unique roles (string references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: 'arn:aws:iam::123456789012:role/lambda-role-1'
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: 'arn:aws:iam::123456789012:role/lambda-role-2'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2]);
      expect(result).toBeNull();
    });

    it('should accept Lambda functions with unique roles (Ref references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 'Ref': 'Role1' }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 'Ref': 'Role2' }
      });
      
      const role1 = createRoleResource({
        LogicalId: 'Role1'
      });
      
      const role2 = createRoleResource({
        LogicalId: 'Role2'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2, role1, role2]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2, role1, role2]);
      expect(result).toBeNull();
    });

    it('should accept Lambda functions with unique roles (GetAtt references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 'Fn::GetAtt': ['Role1', 'Arn'] }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 'Fn::GetAtt': ['Role2', 'Arn'] }
      });
      
      const role1 = createRoleResource({
        LogicalId: 'Role1'
      });
      
      const role2 = createRoleResource({
        LogicalId: 'Role2'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2, role1, role2]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2, role1, role2]);
      expect(result).toBeNull();
    });
  });

  describe('Shared Execution Roles', () => {
    it('should detect Lambda functions with shared roles (string references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: 'arn:aws:iam::123456789012:role/shared-lambda-role'
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: 'arn:aws:iam::123456789012:role/shared-lambda-role' // Same role as Function1
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function shares an IAM execution role with another function/);
    });

    it('should detect Lambda functions with shared roles (Ref references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 'Ref': 'SharedRole' }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 'Ref': 'SharedRole' } // Same role as Function1
      });
      
      const sharedRole = createRoleResource({
        LogicalId: 'SharedRole'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2, sharedRole]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2, sharedRole]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function shares an IAM execution role with another function/);
    });

    it('should detect Lambda functions with shared roles (GetAtt references)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 'Fn::GetAtt': ['SharedRole', 'Arn'] }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 'Fn::GetAtt': ['SharedRole', 'Arn'] } // Same role as Function1
      });
      
      const sharedRole = createRoleResource({
        LogicalId: 'SharedRole'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2, sharedRole]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2, sharedRole]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function shares an IAM execution role with another function/);
    });

    it('should detect Lambda functions with shared roles (mixed reference types)', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 'Ref': 'SharedRole' }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 'Fn::GetAtt': ['SharedRole', 'Arn'] } // Different reference type but same role
      });
      
      const sharedRole = createRoleResource({
        LogicalId: 'SharedRole'
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2, sharedRole]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2, sharedRole]);
      expect(result).not.toBeNull();
      // Note: The rule might not detect this as a shared role due to different reference types
      // This is a limitation of the current implementation
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Role property', () => {
      const lambda = createLambdaResource({
        LogicalId: 'FunctionWithoutRole'
      });
      delete lambda.Properties.Role;
      
      const result = rule.evaluate(lambda, stackName, [lambda]);
      expect(result).toBeNull();
    });

    it('should handle complex intrinsic functions for Role', () => {
      const lambda1 = createLambdaResource({
        LogicalId: 'Function1',
        Role: { 
          'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:role/lambda-role-1'
        }
      });
      
      const lambda2 = createLambdaResource({
        LogicalId: 'Function2',
        Role: { 
          'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:role/lambda-role-2'
        }
      });
      
      // Collect roles for both functions
      rule.evaluate(lambda1, stackName, [lambda1, lambda2]);
      
      // Check the second function (which should be the last one)
      const result = rule.evaluate(lambda2, stackName, [lambda1, lambda2]);
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const lambda = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(lambda, stackName, [lambda]);
      expect(result).toBeNull();
    });

    it('should ignore non-Lambda resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle single Lambda function', () => {
      const lambda = createLambdaResource({
        LogicalId: 'SingleFunction',
        Role: 'arn:aws:iam::123456789012:role/lambda-role'
      });
      
      const result = rule.evaluate(lambda, stackName, [lambda]);
      expect(result).toBeNull();
    });
  });
});
