import { describe, it, expect } from 'vitest';
import { ApiGw007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/007-access-control.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw007Rule', () => {
  const rule = new ApiGw007Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::ApiGateway::RestApi', () => {
      it('should return a finding if a public API has unauthenticated methods', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
        expect(result?.resourceName).toBe('TestApi');
        expect(result?.issue).toContain('API Gateway lacks proper access control');
        expect(result?.issue).toContain('public API with 1 unauthenticated methods');
      });

      it('should not return a finding if a public API has only authenticated methods', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a public API has only OPTIONS methods with no authentication', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a private API has unauthenticated methods', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'private-api',
            EndpointConfiguration: {
              Types: ['PRIVATE']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if an API has VPC policy restrictions', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'api-with-vpc-policy',
            Policy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'execute-api:Invoke',
                  Resource: '*',
                  Condition: {
                    StringEquals: {
                      'aws:SourceVpc': 'vpc-12345678'
                    }
                  }
                }
              ]
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(api, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('AWS::ApiGateway::Method', () => {
      it('should return a finding if a public API method has no authentication', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(method, stackName, [api, method]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Method');
        expect(result?.resourceName).toBe('TestMethod');
        expect(result?.issue).toContain('API Gateway lacks proper access control');
        expect(result?.issue).toContain('public API method with no authentication');
      });

      it('should not return a finding if a public API method has authentication', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(method, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a private API method has no authentication', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'private-api',
            EndpointConfiguration: {
              Types: ['PRIVATE']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(method, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for OPTIONS methods', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(method, stackName, [api, method]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle Ref in AuthorizationType', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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

        // Act
        const result = rule.evaluate(methodWithIamRef, stackName, [api, methodWithIamRef]);

        // Assert
        expect(result).toBeNull(); // Should resolve to AWS_IAM
      });

      it('should handle Fn::Sub in AuthorizationType', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

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
        const result = rule.evaluate(method, stackName, [api, method]);

        // Assert
        expect(result).toBeNull(); // Should resolve to AWS_IAM
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
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'public-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          }
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
