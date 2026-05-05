import { describe, it, expect } from 'vitest';
import { CompLamb016Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/016-container-image-scanning.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb016Rule - Container Image Scanning Tests', () => {
  const rule = new CompLamb016Rule();
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

  // Helper function to create ECR repository test resources
  function createEcrResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::ECR::Repository',
      Properties: {
        RepositoryName: props.RepositoryName || 'my-repo',
        ScanOnPush: props.ScanOnPush !== undefined ? props.ScanOnPush : true,
        Tags: props.Tags || [
          { Key: 'Owner', Value: 'SecurityTeam' }
        ],
        ...props
      },
      LogicalId: props.LogicalId || 'TestEcrRepository'
    };
  }

  describe('Lambda Function Evaluation', () => {
    it('should accept Lambda function with properly configured ECR repository', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      const ecrResource = createEcrResource({
        RepositoryName: 'my-repo',
        ScanOnPush: true,
        Tags: [{ Key: 'Owner', Value: 'SecurityTeam' }]
      });

      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource, ecrResource]);
      expect(result).toBeNull();
    });

    it('should detect Lambda function with ECR repository missing scan-on-push', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      const ecrResource = createEcrResource({
        RepositoryName: 'my-repo',
        ScanOnPush: false,
        Tags: [{ Key: 'Owner', Value: 'SecurityTeam' }]
      });

      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource, ecrResource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies/);
    });

    it('should detect Lambda function with ECR repository missing ownership tags', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      const ecrResource = createEcrResource({
        RepositoryName: 'my-repo',
        ScanOnPush: true,
        Tags: [] // No ownership tags
      });

      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource, ecrResource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies/);
    });

    it('should detect Lambda function with ECR image but no associated repository in template', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:1.0.0'
        }
      });

      // No ECR repository in the template
      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies/);
    });

    it('should detect Lambda function with non-ECR image', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: 'docker.io/library/node:14'
        }
      });

      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies/);
    });

    it('should handle intrinsic functions for ImageUri', () => {
      const lambdaResource = createLambdaResource({
        Code: {
          ImageUri: { 'Ref': 'ImageUriParameter' }
        }
      });

      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toMatch(/Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies/);
    });
  });

  describe('ECR Repository Evaluation', () => {
    // Note: ECR repository scanning checks are now handled by ECR rules
    // These tests are updated to reflect that this rule no longer evaluates ECR repositories directly
    
    it('should accept ECR repository with scan-on-push and ownership tags', () => {
      const ecrResource = createEcrResource({
        ScanOnPush: true,
        Tags: [{ Key: 'Owner', Value: 'SecurityTeam' }]
      });

      const result = rule.evaluate(ecrResource, stackName);
      expect(result).toBeNull(); // Rule now skips ECR resources
    });

    it('should not evaluate ECR repository missing scan-on-push', () => {
      const ecrResource = createEcrResource({
        ScanOnPush: false,
        Tags: [{ Key: 'Owner', Value: 'SecurityTeam' }]
      });

      const result = rule.evaluate(ecrResource, stackName);
      expect(result).toBeNull(); // Rule now skips ECR resources
    });

    it('should not evaluate ECR repository missing ownership tags', () => {
      const ecrResource = createEcrResource({
        ScanOnPush: true,
        Tags: [] // No ownership tags
      });

      const result = rule.evaluate(ecrResource, stackName);
      expect(result).toBeNull(); // Rule now skips ECR resources
    });

    it('should not evaluate ECR repository missing both scan-on-push and ownership tags', () => {
      const ecrResource = createEcrResource({
        ScanOnPush: false,
        Tags: [] // No ownership tags
      });

      const result = rule.evaluate(ecrResource, stackName);
      expect(result).toBeNull(); // Rule now skips ECR resources
    });

    it('should recognize different ownership tag keys', () => {
      const ownershipTags = [
        [{ Key: 'Owner', Value: 'SecurityTeam' }],
        [{ Key: 'Maintainer', Value: 'DevOpsTeam' }],
        [{ Key: 'Team', Value: 'Platform' }],
        [{ Key: 'Department', Value: 'Engineering' }],
        [{ Key: 'Project', Value: 'ServerlessApp' }]
      ];

      for (const tags of ownershipTags) {
        const ecrResource = createEcrResource({
          ScanOnPush: true,
          Tags: tags
        });

        const result = rule.evaluate(ecrResource, stackName);
        expect(result).toBeNull(); // Rule now skips ECR resources
      }
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-Image package type Lambda functions', () => {
      const lambdaResource = createLambdaResource({
        PackageType: 'Zip',
        Code: {
          S3Bucket: 'my-bucket',
          S3Key: 'my-key'
        }
      });

      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Code property', () => {
      const lambdaResource = createLambdaResource({});
      delete lambdaResource.Properties.Code;

      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing ImageUri property', () => {
      const lambdaResource = createLambdaResource({
        Code: {}
      });

      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const lambdaResource = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(lambdaResource, stackName);
      expect(result).toBeNull();
    });

    it('should ignore non-Lambda and non-ECR resources', () => {
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
