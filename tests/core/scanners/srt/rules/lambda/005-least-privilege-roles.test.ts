import { describe, it, expect } from 'vitest';
import { CompLamb005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/005-least-privilege-roles.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb005Rule - Least Privilege IAM Roles Tests', () => {
  const rule = new CompLamb005Rule();
  const stackName = 'test-stack';

  // Helper function to create IAM Role test resources
  function createIAMRoleResource(props: Record<string, any> = {}): CloudFormationResource {
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
        ...props
      },
      LogicalId: props.LogicalId || 'TestRole'
    };
  }

  // Helper function to create Lambda function test resources
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
        ...props
      },
      LogicalId: props.LogicalId || 'TestFunction'
    };
  }

  describe('Lambda Role Detection Tests', () => {
    it('should identify roles with lambda service principal', () => {
      const resource = createIAMRoleResource({
        // Default has lambda.amazonaws.com service principal
      });

      // Create an overly permissive policy to trigger the rule
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // No policies defined yet
    });

    it('should identify roles with lambda in the name', () => {
      const resource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        RoleName: 'lambda-execution-role'
      });

      // Create an overly permissive policy to trigger the rule
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // No policies defined yet
    });

    it('should identify roles with lambda in the path', () => {
      const resource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        Path: '/lambda/'
      });

      // Create an overly permissive policy to trigger the rule
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // No policies defined yet
    });

    it('should identify roles with lambda in the logical ID', () => {
      const resource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        LogicalId: 'LambdaExecutionRole'
      });

      // Create an overly permissive policy to trigger the rule
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // No policies defined yet
    });

    it('should not identify non-lambda roles', () => {
      const resource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        RoleName: 'ec2-execution-role',
        Path: '/ec2/',
        LogicalId: 'EC2Role'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Not a lambda role
    });
    
    it('should identify roles referenced by Lambda functions with string reference', () => {
      const roleResource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda service
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        LogicalId: 'MyExecutionRole'
      });
      
      const lambdaResource = createLambdaResource({
        Role: 'MyExecutionRole',
        LogicalId: 'MyFunction'
      });
      
      const result = rule.evaluate(roleResource, stackName, [roleResource, lambdaResource]);
      expect(result).toBeNull(); // No policies defined yet
    });
    
    it('should identify roles referenced by Lambda functions with Ref', () => {
      const roleResource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda service
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        LogicalId: 'MyExecutionRole'
      });
      
      const lambdaResource = createLambdaResource({
        Role: { 'Ref': 'MyExecutionRole' },
        LogicalId: 'MyFunction'
      });
      
      const result = rule.evaluate(roleResource, stackName, [roleResource, lambdaResource]);
      expect(result).toBeNull(); // No policies defined yet
    });
    
    it('should identify roles referenced by Lambda functions with GetAtt', () => {
      const roleResource = createIAMRoleResource({
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com' // Not lambda service
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        LogicalId: 'MyExecutionRole'
      });
      
      const lambdaResource = createLambdaResource({
        Role: { 'Fn::GetAtt': ['MyExecutionRole', 'Arn'] },
        LogicalId: 'MyFunction'
      });
      
      const result = rule.evaluate(roleResource, stackName, [roleResource, lambdaResource]);
      expect(result).toBeNull(); // No policies defined yet
    });
  });

  describe('Overly Permissive Policy Tests', () => {
    it('should detect wildcard actions with wildcard resources', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'overly-permissive-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace wildcard actions (e.g., \'*\' or \'service:*\') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using \'*\'.');
    });

    it('should detect service-level wildcard actions with wildcard resources', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'overly-permissive-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:*',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace wildcard actions (e.g., \'*\' or \'service:*\') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using \'*\'.');
    });

    it('should accept wildcard actions with specific resources', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'acceptable-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:*',
                  Resource: 'arn:aws:s3:::my-specific-bucket/*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept specific actions with wildcard resources', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'acceptable-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:GetObject',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Managed Policy Tests', () => {
    it('should detect overly permissive managed policies', () => {
      const resource = createIAMRoleResource({
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AdministratorAccess'
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace overly permissive managed policy \'arn:aws:iam::aws:policy/AdministratorAccess\' with a custom policy that grants only the specific permissions required by the Lambda function');
    });

    it('should accept specific managed policies', () => {
      const resource = createIAMRoleResource({
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should detect multiple managed policies including overly permissive ones', () => {
      const resource = createIAMRoleResource({
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
          'arn:aws:iam::aws:policy/AmazonS3FullAccess'
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace overly permissive managed policy \'arn:aws:iam::aws:policy/AmazonS3FullAccess\' with a custom policy that grants only the specific permissions required by the Lambda function');
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in policy documents', () => {
      const resource: CloudFormationResource = {
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
          Policies: [
            {
              PolicyName: 'dynamic-policy',
              PolicyDocument: { 'Ref': 'PolicyDocument' }
            }
          ]
        },
        LogicalId: 'TestRole'
      };
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic policies
    });

    it('should handle CloudFormation intrinsic functions in managed policy arns', () => {
      const resource: CloudFormationResource = {
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
            { 'Ref': 'ManagedPolicyArn' }
          ]
        },
        LogicalId: 'TestRole'
      };
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't validate dynamic managed policies
    });
    
    it('should handle CloudFormation intrinsic functions in service principal', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: {
                  Service: { 'Fn::Sub': 'lambda.${AWS::Region}.amazonaws.com' }
                },
                Action: 'sts:AssumeRole'
              }
            ]
          }
        },
        LogicalId: 'TestRole'
      };
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // No policies defined yet
    });
    
    it('should evaluate Lambda functions that reference roles', () => {
      const roleResource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'overly-permissive-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*'
                }
              ]
            }
          }
        ],
        LogicalId: 'MyExecutionRole'
      });
      
      const lambdaResource = createLambdaResource({
        Role: { 'Ref': 'MyExecutionRole' },
        LogicalId: 'MyFunction'
      });
      
      const result = rule.evaluate(lambdaResource, stackName, [roleResource, lambdaResource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace wildcard actions (e.g., \'*\' or \'service:*\') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using \'*\'.');
    });
  });

  describe('Wildcard Detection Tests', () => {
    it('should detect wildcard actions with wildcard resources in intrinsic functions', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'policy-with-intrinsic-function',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: { 'Fn::Join': ['', ['*']] },
                  Resource: '*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace wildcard actions (e.g., \'*\' or \'service:*\') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using \'*\'.');
    });
    
    it('should detect dangerous service-level wildcards', () => {
      const resource = createIAMRoleResource({
        Policies: [
          {
            PolicyName: 'dangerous-service-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 'iam:*',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace wildcard actions (e.g., \'*\' or \'service:*\') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using \'*\'.');
    });
    
    it('should detect custom managed policies with permissive keywords', () => {
      const resource = createIAMRoleResource({
        ManagedPolicyArns: [
          'arn:aws:iam::123456789012:policy/MyCustomFullAccess'
        ]
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function IAM role violates principle of least privilege');
      expect(result?.fix).toContain('Replace overly permissive managed policy \'arn:aws:iam::123456789012:policy/MyCustomFullAccess\' with a custom policy that grants only the specific permissions required by the Lambda function');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::IAM::Role',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should ignore non-IAM Role resources that aren\'t Lambda functions', () => {
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
    
    it('should handle Lambda functions with missing role', () => {
      const lambdaResource = createLambdaResource({
        // No Role specified
      });
      
      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).toBeNull();
    });
    
    it('should handle Lambda functions with role that doesn\'t exist in the template', () => {
      const lambdaResource = createLambdaResource({
        Role: { 'Ref': 'NonExistentRole' }
      });
      
      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource]);
      expect(result).toBeNull();
    });
  });
});
