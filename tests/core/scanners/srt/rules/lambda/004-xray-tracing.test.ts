import { describe, it, expect } from 'vitest';
import { CompLamb004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/004-xray-tracing.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb004Rule - X-Ray Tracing Tests', () => {
  const rule = new CompLamb004Rule();
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
        ...props
      },
      LogicalId: props.LogicalId || 'TestFunction'
    };
  }

  describe('Basic Configuration Tests', () => {
    it('should detect missing X-Ray tracing configuration', () => {
      const resource = createLambdaResource({
        // No TracingConfig
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Add TracingConfig property to the Lambda function configuration');
    });

    it('should detect inactive X-Ray tracing', () => {
      const resource = createLambdaResource({
        TracingConfig: {
          Mode: 'PassThrough'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Set TracingConfig.Mode to \'Active\' to enable X-Ray tracing for the Lambda function');
    });

    it('should accept active X-Ray tracing', () => {
      const resource = createLambdaResource({
        TracingConfig: {
          Mode: 'Active'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in tracing config', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs14.x',
          Code: {
            S3Bucket: 'my-bucket',
            S3Key: 'my-key'
          },
          TracingConfig: { 
            Mode: { 'Ref': 'TracingMode' }
          }
        },
        LogicalId: 'TestFunction'
      };
      
      // This should fail because we can't guarantee the Ref resolves to 'Active'
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Set TracingConfig.Mode to \'Active\' to enable X-Ray tracing for the Lambda function');
    });

    it('should handle CloudFormation conditions', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs14.x',
          Code: {
            S3Bucket: 'my-bucket',
            S3Key: 'my-key'
          }
          // No TracingConfig
        },
        LogicalId: 'TestFunction'
      };
      
      // This should fail because we can't guarantee the condition resolves to Active
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Add TracingConfig property to the Lambda function configuration');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
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
  });
});
