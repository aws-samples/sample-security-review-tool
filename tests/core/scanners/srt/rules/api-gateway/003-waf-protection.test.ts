import { describe, it, expect } from 'vitest';
import { ApiGw003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/003-waf-protection.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw003Rule', () => {
  const rule = new ApiGw003Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::ApiGateway::Stage', () => {
      it('should return a finding if a public API Stage has no WAF protection', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' }
          },
          LogicalId: 'TestStage'
        };

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
        const result = rule.evaluate(stage, stackName, [stage, api]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
        expect(result?.resourceName).toBe('TestStage');
        expect(result?.issue).toContain('Public API Gateway endpoint lacks WAF protection');
        expect(result?.fix).toContain('Create an AWS::WAFv2::WebACL and associate it with this API Gateway stage');
      });

      it('should not return a finding if a private API Stage has no WAF protection', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' }
          },
          LogicalId: 'TestStage'
        };

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

        // Act
        const result = rule.evaluate(stage, stackName, [stage, api]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a public API Stage has WAF protection via WebACLAssociation', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: { Ref: 'TestApi' }
          },
          LogicalId: 'TestStage'
        };

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

        const webAcl: CloudFormationResource = {
          Type: 'AWS::WAFv2::WebACL',
          Properties: {
            Name: 'TestWebACL',
            Scope: 'REGIONAL',
            DefaultAction: {
              Allow: {}
            },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: 'TestWebACL'
            }
          },
          LogicalId: 'TestWebACL'
        };

        const webAclAssociation: CloudFormationResource = {
          Type: 'AWS::WAFv2::WebACLAssociation',
          Properties: {
            ResourceArn: { 'Fn::GetAtt': ['TestStage', 'StageArn'] },
            WebACLArn: { 'Fn::GetAtt': ['TestWebACL', 'Arn'] }
          },
          LogicalId: 'TestWebACLAssociation'
        };

        // Act
        const result = rule.evaluate(stage, stackName, [stage, api, webAcl, webAclAssociation]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if WAF is associated via Fn::Join ARN (CDK pattern)', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'v1',
            RestApiId: { Ref: 'GamsApi' }
          },
          LogicalId: 'GamsApiDeploymentStagev1'
        };

        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'GAMS API',
            EndpointConfiguration: { Types: ['REGIONAL'] }
          },
          LogicalId: 'GamsApi'
        };

        const webAcl: CloudFormationResource = {
          Type: 'AWS::WAFv2::WebACL',
          Properties: { Name: 'GamsApiWaf', Scope: 'REGIONAL' },
          LogicalId: 'GamsApiWaf'
        };

        const webAclAssociation: CloudFormationResource = {
          Type: 'AWS::WAFv2::WebACLAssociation',
          Properties: {
            ResourceArn: {
              'Fn::Join': ['', [
                'arn:aws:apigateway:',
                { Ref: 'AWS::Region' },
                '::/restapis/',
                { Ref: 'GamsApi' },
                '/stages/v1'
              ]]
            },
            WebACLArn: { 'Fn::GetAtt': ['GamsApiWaf', 'Arn'] }
          },
          LogicalId: 'GamsApiWafAssociation'
        };

        // Act
        const result = rule.evaluate(stage, stackName, [stage, api, webAcl, webAclAssociation]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle stage with no RestApiId', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'internal',
          },
          LogicalId: 'TestStage'
        };

        // Act
        const result = rule.evaluate(stage, stackName, [stage]);

        // Assert
        expect(result).toBeNull(); // Should not return a finding for internal stage name
      });

      it('should handle stage with public name indicators', () => {
        // Arrange
        const stage: CloudFormationResource = {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'production',
          },
          LogicalId: 'TestStage'
        };

        // Act
        const result = rule.evaluate(stage, stackName, [stage]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
        expect(result?.resourceName).toBe('TestStage');
        expect(result?.issue).toContain('Public API Gateway endpoint lacks WAF protection');
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
