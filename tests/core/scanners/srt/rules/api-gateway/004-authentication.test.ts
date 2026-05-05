import { describe, it, expect } from 'vitest';
import { ApiGw004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/004-authentication.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw004Rule', () => {
  const rule = new ApiGw004Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a Method has no AuthorizationType', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
      expect(result?.resourceName).toBe('TestMethod');
      expect(result?.issue).toContain('API Gateway lacks proper authentication configuration');
      expect(result?.issue).toContain('AuthorizationType is not specified');
    });

    it('should return a finding if a Method has AuthorizationType set to NONE', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'NONE',
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
      expect(result?.resourceName).toBe('TestMethod');
      expect(result?.issue).toContain('API Gateway lacks proper authentication configuration');
      expect(result?.issue).toContain('AuthorizationType is NONE');
    });

    it('should return a finding if a Method has CUSTOM AuthorizationType but no AuthorizerId', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'CUSTOM',
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
      expect(result?.resourceName).toBe('TestMethod');
      expect(result?.issue).toContain('API Gateway lacks proper authentication configuration');
      expect(result?.issue).toContain('CUSTOM specified but AuthorizerId is missing');
    });

    it('should return a finding if a Method has COGNITO_USER_POOLS AuthorizationType but no AuthorizerId', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'COGNITO_USER_POOLS',
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
      expect(result?.resourceName).toBe('TestMethod');
      expect(result?.issue).toContain('API Gateway lacks proper authentication configuration');
      expect(result?.issue).toContain('COGNITO_USER_POOLS specified but AuthorizerId is missing');
    });

    it('should not return a finding if a Method has AWS_IAM AuthorizationType', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'AWS_IAM',
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a Method has CUSTOM AuthorizationType with AuthorizerId', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'CUSTOM',
          AuthorizerId: { Ref: 'TestAuthorizer' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a Method has COGNITO_USER_POOLS AuthorizationType with AuthorizerId', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'COGNITO_USER_POOLS',
          AuthorizerId: { Ref: 'TestAuthorizer' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding for OPTIONS methods', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'OPTIONS',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: 'NONE',
          Integration: {
            Type: 'MOCK',
            IntegrationResponses: [
              {
                StatusCode: '200',
                ResponseParameters: {
                  'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key'",
                  'method.response.header.Access-Control-Allow-Methods': "'GET,POST,PUT,DELETE,OPTIONS'",
                  'method.response.header.Access-Control-Allow-Origin': "'*'"
                }
              }
            ]
          }
        },
        LogicalId: 'TestOptionsMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle Ref in AuthorizationType', () => {
      // Arrange
      const methodWithIamRef: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: { Ref: 'IAMAuthType' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethodWithIamRef'
      };

      const methodWithCognitoRef: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: { Ref: 'CognitoAuthType' },
          AuthorizerId: { Ref: 'TestAuthorizer' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethodWithCognitoRef'
      };

      // Act
      const iamResult = rule.evaluate(methodWithIamRef, stackName);
      const cognitoResult = rule.evaluate(methodWithCognitoRef, stackName);

      // Assert
      expect(iamResult).toBeNull(); // Should resolve to AWS_IAM
      expect(cognitoResult).toBeNull(); // Should resolve to COGNITO_USER_POOLS
    });

    it('should handle Fn::Sub in AuthorizationType', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'GET',
          ResourceId: { Ref: 'ApiResource' },
          RestApiId: { Ref: 'TestApi' },
          AuthorizationType: { 'Fn::Sub': 'AWS_IAM' },
          Integration: {
            Type: 'AWS_PROXY',
            IntegrationHttpMethod: 'POST',
            Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
          }
        },
        LogicalId: 'TestMethod'
      };

      // Act
      const result = rule.evaluate(method, stackName);

      // Assert
      expect(result).toBeNull(); // Should resolve to AWS_IAM
    });

    it('should return null for non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
