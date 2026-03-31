import { describe, it, expect } from 'vitest';
import { ApiGw009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/009-private-endpoints.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw009Rule', () => {
  const rule = new ApiGw009Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if no endpoint configuration is specified', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api'
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
      expect(result?.issue).toContain('no endpoint configuration specified, defaults to public');
    });

    it('should return a finding if endpoint configuration does not include PRIVATE', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          }
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
      expect(result?.issue).toContain('endpoint type is REGIONAL');
    });

    it('should return a finding if endpoint configuration is empty', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {}
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
      expect(result?.issue).toContain('endpoint type is not specified');
    });

    it('should return a finding if endpoint configuration types is not an array', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: 'REGIONAL' // Not an array
          }
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
    });

    it('should not return a finding if endpoint configuration includes PRIVATE', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['PRIVATE']
          }
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if API has PublicAccess=Required tag', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'PublicAccess',
              Value: 'Required'
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if API has PublicAPI=True tag', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'PublicAPI',
              Value: 'True'
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if API has InternetFacing=True tag', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'InternetFacing',
              Value: 'True'
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if API has PublicAccessJustification tag with value', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'PublicAccessJustification',
              Value: 'This API needs to be accessible from the Internet for mobile app integration.'
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if API has PublicAccessJustification tag with empty value', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'PublicAccessJustification',
              Value: ''
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
    });

    it('should return a finding if API has unrelated tags', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'test-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          },
          Tags: [
            {
              Key: 'Environment',
              Value: 'Production'
            },
            {
              Key: 'Owner',
              Value: 'Team A'
            }
          ]
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
      expect(result?.resourceName).toBe('TestApi');
      expect(result?.issue).toContain('API Gateway is publicly accessible without justification');
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
