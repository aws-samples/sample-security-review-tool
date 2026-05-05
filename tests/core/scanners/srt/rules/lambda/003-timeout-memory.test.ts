import { describe, it, expect } from 'vitest';
import { CompLamb003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/003-timeout-memory.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb003Rule - Timeout and Memory Tests', () => {
  const rule = new CompLamb003Rule();
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

  describe('Timeout Configuration Tests', () => {
    it('should detect timeout that is too high', () => {
      const resource = createLambdaResource({
        Timeout: 901 // > 15 minutes (900 seconds)
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function has inappropriate timeout or memory configuration');
      expect(result?.fix).toContain('Configure Timeout between 3 and 900 seconds based on the function\'s expected execution time');
    });

    it('should detect timeout that is too low', () => {
      const resource = createLambdaResource({
        Timeout: 2 // < 3 seconds
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function has inappropriate timeout or memory configuration');
      expect(result?.fix).toContain('Configure Timeout between 3 and 900 seconds based on the function\'s expected execution time.');
    });

    it('should accept timeout within acceptable range', () => {
      const resource = createLambdaResource({
        Timeout: 30 // 30 seconds
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept timeout at lower boundary', () => {
      const resource = createLambdaResource({
        Timeout: 3 // 3 seconds
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept timeout at upper boundary', () => {
      const resource = createLambdaResource({
        Timeout: 900 // 15 minutes
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Memory Configuration Tests', () => {
    it('should detect memory that is too low', () => {
      const resource = createLambdaResource({
        MemorySize: 127 // < 128MB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function has inappropriate timeout or memory configuration');
      expect(result?.fix).toContain('Configure MemorySize between 128 MB and 3072 MB based on the function\'s memory requirements');
    });

    it('should detect memory that is too high for standard functions', () => {
      const resource = createLambdaResource({
        MemorySize: 3073 // > 3GB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function has inappropriate timeout or memory configuration');
      expect(result?.fix).toContain('Configure MemorySize between 128 MB and 3072 MB based on the function\'s memory requirements');
    });

    it('should accept memory within acceptable range', () => {
      const resource = createLambdaResource({
        MemorySize: 1024 // 1GB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept memory at lower boundary', () => {
      const resource = createLambdaResource({
        MemorySize: 128 // 128MB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept memory at upper boundary', () => {
      const resource = createLambdaResource({
        MemorySize: 3072 // 3GB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('High Memory Function Detection', () => {
    it('should accept high memory for image processing functions', () => {
      const resource = createLambdaResource({
        FunctionName: 'image-processor',
        MemorySize: 4096 // 4GB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept high memory for ML inference functions', () => {
      const resource = createLambdaResource({
        Handler: 'index.predict',
        MemorySize: 5120 // 5GB
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
    
    it('should accept high memory for functions with memory-intensive runtimes', () => {
      const resource = createLambdaResource({
        MemorySize: 6144, // 6GB
        Runtime: 'java11'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
    
    it('should reject extremely high memory even for high-memory functions', () => {
      const resource = createLambdaResource({
        FunctionName: 'image-processor',
        MemorySize: 12288 // 12GB - beyond the high memory limit
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Lambda function has inappropriate timeout or memory configuration');
      expect(result?.fix).toContain('Configure MemorySize between 128 MB and 10240 MB based on the function\'s memory requirements.');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing timeout and memory', () => {
      const resource = createLambdaResource({
        // No timeout or memory specified
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
    
    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
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
    
    it('should skip parameterized timeout values', () => {
      const resource = createLambdaResource({
        Timeout: { 'Ref': 'LambdaTimeout' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
    
    it('should skip parameterized memory values', () => {
      const resource = createLambdaResource({
        MemorySize: { 'Ref': 'LambdaMemorySize' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
    
    it('should use logical ID for high memory detection when function name is parameterized', () => {
      const resource = createLambdaResource({
        FunctionName: { 'Ref': 'FunctionName' },
        MemorySize: 6144, // 6GB
        LogicalId: 'ImageProcessingFunction'
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
