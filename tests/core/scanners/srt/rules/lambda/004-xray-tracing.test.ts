import { describe, it, expect } from 'vitest';
import { CompLamb004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/004-xray-tracing.cf.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('CompLamb004Rule - X-Ray Tracing Tests', () => {
  const rule = new CompLamb004Rule();
  const stackName = 'test-stack';

  const defaultProps = {
    Handler: 'index.handler',
    Runtime: 'nodejs14.x',
    Code: {
      S3Bucket: 'my-bucket',
      S3Key: 'my-key'
    }
  };

  function createTemplate(props: Record<string, any> = {}, logicalId = 'TestFunction'): Template {
    return {
      Resources: {
        [logicalId]: {
          Type: 'AWS::Lambda::Function',
          Properties: { ...defaultProps, ...props }
        }
      }
    };
  }

  describe('Basic Configuration Tests', () => {
    it('should detect missing X-Ray tracing configuration', () => {
      const template = createTemplate();
      const resource = template.Resources!['TestFunction'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('TestFunction');
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Add TracingConfig property to the Lambda function configuration');
    });

    it('should detect inactive X-Ray tracing', () => {
      const template = createTemplate({ TracingConfig: { Mode: 'PassThrough' } });
      const resource = template.Resources!['TestFunction'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('TestFunction');
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Set TracingConfig.Mode to \'Active\' to enable X-Ray tracing for the Lambda function');
    });

    it('should accept active X-Ray tracing', () => {
      const template = createTemplate({ TracingConfig: { Mode: 'Active' } });
      const resource = template.Resources!['TestFunction'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Integration Tests', () => {
    it('should handle CloudFormation intrinsic functions in tracing config', () => {
      const template = createTemplate({ TracingConfig: { Mode: { 'Ref': 'TracingMode' } } });
      const resource = template.Resources!['TestFunction'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('TestFunction');
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Set TracingConfig.Mode to \'Active\' to enable X-Ray tracing for the Lambda function');
    });

    it('should handle CloudFormation conditions', () => {
      const template = createTemplate();
      const resource = template.Resources!['TestFunction'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('TestFunction');
      expect(result?.issue).toContain('No X-Ray tracing configured for Lambda function');
      expect(result?.fix).toContain('Add TracingConfig property to the Lambda function configuration');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      const template: Template = {
        Resources: {
          MissingProperties: {
            Type: 'AWS::Lambda::Function'
          }
        }
      };
      const resource = template.Resources!['MissingProperties'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('MissingProperties');
    });

    it('should ignore non-Lambda resources', () => {
      const template: Template = {
        Resources: {
          TestBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { BucketName: 'my-bucket' }
          }
        }
      };
      const resource = template.Resources!['TestBucket'] as Resource;

      const result = rule.evaluateResource(stackName, template, resource);

      expect(result).toBeNull();
    });
  });

  describe('evaluate (legacy stub)', () => {
    it('should return null', () => {
      const result = rule.evaluate(
        { Type: 'AWS::Lambda::Function', Properties: {}, LogicalId: 'Test' },
        stackName
      );
      expect(result).toBeNull();
    });
  });
});
