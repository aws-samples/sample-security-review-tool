import { describe, it, expect } from 'vitest';
import { CompLamb015Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/015-container-image-repository.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb015Rule - Container Image Repository Tests', () => {
  const rule = new CompLamb015Rule();
  const stackName = 'test-stack';

  // Helper function to create Lambda test resources
  function createLambdaResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Lambda::Function',
      Properties: {
        PackageType: props.PackageType || 'Image',
        Code: props.Code || {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestFunction'
    };
  }

  describe('Secure Repositories', () => {
    it('should accept Lambda function with ECR image', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept Lambda function with AWS Public ECR image', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: 'public.ecr.aws/lambda/nodejs:16'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept Lambda function with other secure repository images', () => {
      const secureRepos = [
        'mycompany.jfrog.io/my-repo:1.0.0',
        'myregistry.azurecr.io/my-repo:1.0.0',
        'gcr.io/my-project/my-repo:1.0.0',
        'registry.gitlab.com/my-group/my-repo:1.0.0',
        'ghcr.io/my-org/my-repo:1.0.0'
      ];

      for (const repo of secureRepos) {
        const resource = createLambdaResource({
          Code: {
            ImageUri: repo
          }
        });

        const result = rule.evaluate(resource, stackName);
        expect(result).toBeNull();
      }
    });
  });

  describe('Insecure Repositories', () => {
    it('should detect Lambda function with Docker Hub image (no organization)', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: 'nginx:latest'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });

    it('should detect Lambda function with Docker Hub library image', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: 'docker.io/library/node:14'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });

    it('should detect Lambda function with public registry image', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: 'quay.io/bitnami/node:14'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });
  });

  describe('Image Tags', () => {
    it('should detect Lambda function with latest tag', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });

    it('should detect Lambda function with no tag', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });
  });

  describe('Reference Handling', () => {
    it('should handle intrinsic functions for ImageUri', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: { 'Ref': 'ImageUriParameter' }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });

    it('should handle Sub intrinsic function for ImageUri', () => {
      const resource = createLambdaResource({
        Code: {
          ImageUri: { 'Fn::Sub': '${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/my-repo:1.0.0' }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda function container image may not be stored in a secure repository/);
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-Image package type Lambda functions', () => {
      const resource = createLambdaResource({
        PackageType: 'Zip',
        Code: {
          S3Bucket: 'my-bucket',
          S3Key: 'my-key'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Code property', () => {
      const resource = createLambdaResource({});
      delete resource.Properties.Code;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing ImageUri property', () => {
      const resource = createLambdaResource({
        Code: {}
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

    it('should handle intrinsic function for PackageType', () => {
      const resource = createLambdaResource({
        PackageType: { 'Ref': 'PackageTypeParameter' },
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
