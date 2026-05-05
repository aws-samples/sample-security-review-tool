import { describe, it, expect } from 'vitest';
import { ApiGw002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/002-request-validation.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw002Rule', () => {
  const rule = new ApiGw002Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::ApiGateway::Method', () => {
      it('should return null when evaluating a Method (findings only at RestApi level)', () => {
        // Arrange
        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
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

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api]);

        // Assert - findings are consolidated at RestApi level
        expect(result).toBeNull();
      });

      it('should not return a finding if a Method has a valid RequestValidatorId', () => {
        // Arrange
        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
            ResourceId: { Ref: 'ApiResource' },
            RestApiId: { Ref: 'TestApi' },
            AuthorizationType: 'NONE',
            RequestValidatorId: { Ref: 'TestValidator' },
            Integration: {
              Type: 'AWS_PROXY',
              IntegrationHttpMethod: 'POST',
              Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
            }
          },
          LogicalId: 'TestMethod'
        };

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const validator: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: { Ref: 'TestApi' },
            ValidateRequestBody: true,
            ValidateRequestParameters: true
          },
          LogicalId: 'TestValidator'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api, validator]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a Method has RequestModels', () => {
        // Arrange
        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
            ResourceId: { Ref: 'ApiResource' },
            RestApiId: { Ref: 'TestApi' },
            AuthorizationType: 'NONE',
            RequestModels: {
              'application/json': { Ref: 'ApiModel' }
            },
            Integration: {
              Type: 'AWS_PROXY',
              IntegrationHttpMethod: 'POST',
              Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
            }
          },
          LogicalId: 'TestMethod'
        };

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api]);

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

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle string RequestValidatorId', () => {
        // Arrange
        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
            ResourceId: { Ref: 'ApiResource' },
            RestApiId: { Ref: 'TestApi' },
            AuthorizationType: 'NONE',
            RequestValidatorId: 'TestValidator',
            Integration: {
              Type: 'AWS_PROXY',
              IntegrationHttpMethod: 'POST',
              Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
            }
          },
          LogicalId: 'TestMethod'
        };

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const validator: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: { Ref: 'TestApi' },
            ValidateRequestBody: true,
            ValidateRequestParameters: true
          },
          LogicalId: 'TestValidator'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api, validator]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle Fn::GetAtt in RequestValidatorId', () => {
        // Arrange
        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
            ResourceId: { Ref: 'ApiResource' },
            RestApiId: { Ref: 'TestApi' },
            AuthorizationType: 'NONE',
            RequestValidatorId: { 'Fn::GetAtt': ['TestValidator', 'RequestValidatorId'] },
            Integration: {
              Type: 'AWS_PROXY',
              IntegrationHttpMethod: 'POST',
              Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
            }
          },
          LogicalId: 'TestMethod'
        };

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const validator: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: { Ref: 'TestApi' },
            ValidateRequestBody: true,
            ValidateRequestParameters: true
          },
          LogicalId: 'TestValidator'
        };

        // Act
        const result = rule.evaluate(method, stackName, [method, api, validator]);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('AWS::ApiGateway::RestApi', () => {
      it('should return a finding if an API has methods without validation', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
        expect(result?.resourceName).toBe('TestApi');
        expect(result?.issue).toContain('API Gateway has 1 method(s) without request validation');
      });

      it('should return a finding if API has validator but method does not use it', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
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

        const validator: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: { Ref: 'TestApi' },
            ValidateRequestBody: true,
            ValidateRequestParameters: true
          },
          LogicalId: 'TestValidator'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, method, validator]);

        // Assert - finding because method doesn't have RequestValidatorId
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('API Gateway has 1 method(s) without request validation');
      });

      it('should not return a finding if all methods have validation', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        const method: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            HttpMethod: 'POST',
            ResourceId: { Ref: 'ApiResource' },
            RestApiId: { Ref: 'TestApi' },
            AuthorizationType: 'NONE',
            RequestValidatorId: { Ref: 'TestValidator' },
            Integration: {
              Type: 'AWS_PROXY',
              IntegrationHttpMethod: 'POST',
              Uri: { 'Fn::Sub': 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations' }
            }
          },
          LogicalId: 'TestMethod'
        };

        const validator: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RequestValidator',
          Properties: {
            RestApiId: { Ref: 'TestApi' },
            ValidateRequestBody: true,
            ValidateRequestParameters: true
          },
          LogicalId: 'TestValidator'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, method, validator]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if an API has no methods', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'test-api'
          },
          LogicalId: 'TestApi'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api]);

        // Assert
        expect(result).toBeNull();
      });
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
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if allResources is not provided', () => {
      // Arrange
      const method: CloudFormationResource = {
        Type: 'AWS::ApiGateway::Method',
        Properties: {
          HttpMethod: 'POST',
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
      expect(result).toBeNull();
    });
  });
});
