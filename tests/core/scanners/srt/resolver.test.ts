import { describe, it, expect } from 'vitest';
import { CloudFormationResolver } from '../../../../src/assess/scanning/security-matrix/resolver.js';
import { CloudFormationResource } from '../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CloudFormationResolver', () => {
  // Helper function to create test resources
  function createTestResource(type: string, properties: Record<string, any> = {}, logicalId: string = 'TestResource'): CloudFormationResource {
    return {
      Type: type,
      Properties: properties,
      LogicalId: logicalId
    };
  }

  describe('Constructor Tests', () => {
    it('should initialize with empty resources when none provided', () => {
      const resolver = new CloudFormationResolver();
      expect(resolver.getResource('NonExistentResource')).toBeNull();
    });

    it('should initialize with provided resources', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      expect(resolver.getResource('TestBucket')).not.toBeNull();
      expect(resolver.getResource('TestBucket').Type).toBe('AWS::S3::Bucket');
    });

    it('should handle multiple resources', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket'),
        createTestResource('AWS::Lambda::Function', { Handler: 'index.handler' }, 'TestFunction')
      ];
      const resolver = new CloudFormationResolver(resources);
      expect(resolver.getResource('TestBucket')).not.toBeNull();
      expect(resolver.getResource('TestFunction')).not.toBeNull();
    });

    it('should handle resources with missing properties', () => {
      const resource = {
        Type: 'AWS::S3::Bucket',
        LogicalId: 'BucketWithoutProperties'
      } as CloudFormationResource;
      
      const resolver = new CloudFormationResolver([resource]);
      const retrievedResource = resolver.getResource('BucketWithoutProperties');
      expect(retrievedResource).not.toBeNull();
      // The implementation doesn't initialize Properties to an empty object if it's missing
      expect(retrievedResource.Properties).toBeUndefined();
    });
  });

  describe('Simple Value Resolution Tests', () => {
    it('should resolve string values directly', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve('simple string');
      expect(result.value).toBe('simple string');
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should resolve number values directly', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve(42);
      expect(result.value).toBe(42);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should resolve boolean values directly', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve(true);
      expect(result.value).toBe(true);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should resolve null values directly', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve(null);
      expect(result.value).toBe(null);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should treat string values as external references when option is set', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve('external reference', { treatLiteralStringsAs: 'external-references' });
      expect(result.value).toBe(null);
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toEqual([]);
    });
  });

  describe('Array Resolution Tests', () => {
    it('should resolve arrays of simple values', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve(['string', 42, true, null]);
      expect(result.value).toEqual(['string', 42, true, null]);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should resolve arrays with mixed values', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const result = resolver.resolve(['string', { Ref: 'TestBucket' }]);
      // The implementation resolves the array even if it contains references
      expect(result.value).toEqual(['string', 'TestBucket']);
      // Since all references are resolved, isResolved is true
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toContain('TestBucket');
    });

    it('should resolve arrays with all resolvable references', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket'),
        createTestResource('AWS::Lambda::Function', { Handler: 'index.handler' }, 'TestFunction')
      ];
      const resolver = new CloudFormationResolver(resources);
      const result = resolver.resolve([{ Ref: 'TestBucket' }, { Ref: 'TestFunction' }]);
      expect(result.value).toEqual(['TestBucket', 'TestFunction']);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toContain('TestBucket');
      expect(result.referencedResources).toContain('TestFunction');
    });

    it('should handle nested arrays', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve([['nested', 'array'], [1, 2, 3]]);
      expect(result.value).toEqual([['nested', 'array'], [1, 2, 3]]);
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual([]);
    });

    it('should handle arrays with unresolvable references', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve(['string', { Ref: 'NonExistentResource' }]);
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toContain('NonExistentResource');
    });
  });

  describe('Object Resolution Tests', () => {
    it('should resolve Ref to a defined resource', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const result = resolver.resolve({ Ref: 'TestBucket' });
      expect(result.value).toBe('TestBucket');
      expect(result.isResolved).toBe(true);
      expect(result.referencedResources).toEqual(['TestBucket']);
    });

    it('should handle Ref to undefined resource', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve({ Ref: 'NonExistentResource' });
      expect(result.value).toBe('NonExistentResource');
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toEqual(['NonExistentResource']);
    });

    it('should handle GetAtt function', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const result = resolver.resolve({ 'Fn::GetAtt': ['TestBucket', 'Arn'] });
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toEqual(['TestBucket']);
    });

    it('should handle GetAtt function with string notation', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const result = resolver.resolve({ 'Fn::GetAtt': 'TestBucket.Arn' });
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      // The implementation keeps the full string as the reference
      expect(result.referencedResources).toEqual(['TestBucket.Arn']);
    });

    it('should handle other intrinsic functions', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve({ 'Fn::Join': ['', ['Hello', 'World']] });
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toEqual([]);
    });

    it('should extract references from nested objects', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve({
        'Fn::Join': [
          '',
          [
            'arn:aws:s3:::',
            { Ref: 'BucketName' },
            '/*'
          ]
        ]
      });
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toContain('BucketName');
    });

    it('should extract multiple references from complex objects', () => {
      const resolver = new CloudFormationResolver();
      const result = resolver.resolve({
        'Fn::Sub': [
          '${BucketName}-${AWS::Region}',
          {
            BucketName: { Ref: 'BucketParameter' }
          }
        ]
      });
      expect(result.value).toBeNull();
      expect(result.isResolved).toBe(false);
      expect(result.referencedResources).toContain('BucketParameter');
    });
  });

  describe('Resource Retrieval Tests', () => {
    it('should get resource by logical ID', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const resource = resolver.getResource('TestBucket');
      expect(resource).not.toBeNull();
      expect(resource.Type).toBe('AWS::S3::Bucket');
      expect(resource.Properties.BucketName).toBe('test-bucket');
    });

    it('should return null for non-existent resource', () => {
      const resolver = new CloudFormationResolver();
      const resource = resolver.getResource('NonExistentResource');
      expect(resource).toBeNull();
    });

    it('should get resources by type', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'bucket-1' }, 'Bucket1'),
        createTestResource('AWS::S3::Bucket', { BucketName: 'bucket-2' }, 'Bucket2'),
        createTestResource('AWS::Lambda::Function', { Handler: 'index.handler' }, 'Function1')
      ];
      const resolver = new CloudFormationResolver(resources);
      const buckets = resolver.getResourcesByType('AWS::S3::Bucket');
      expect(buckets.length).toBe(2);
      expect(buckets[0].LogicalId).toBe('Bucket1');
      expect(buckets[1].LogicalId).toBe('Bucket2');
    });

    it('should return empty array for non-existent resource type', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'test-bucket' }, 'TestBucket')
      ];
      const resolver = new CloudFormationResolver(resources);
      const dynamoTables = resolver.getResourcesByType('AWS::DynamoDB::Table');
      expect(dynamoTables).toEqual([]);
    });
  });

  describe('Integration Tests', () => {
    it('should handle complex CloudFormation template with multiple resource types', () => {
      const resources = [
        createTestResource('AWS::S3::Bucket', { BucketName: 'data-bucket' }, 'DataBucket'),
        createTestResource('AWS::IAM::Role', {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'lambda.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        }, 'LambdaExecutionRole'),
        createTestResource('AWS::Lambda::Function', {
          Handler: 'index.handler',
          Role: { 'Fn::GetAtt': ['LambdaExecutionRole', 'Arn'] },
          Environment: {
            Variables: {
              BUCKET_NAME: { Ref: 'DataBucket' }
            }
          }
        }, 'ProcessingFunction')
      ];
      
      const resolver = new CloudFormationResolver(resources);
      
      // Test resource retrieval
      expect(resolver.getResource('DataBucket')).not.toBeNull();
      expect(resolver.getResource('LambdaExecutionRole')).not.toBeNull();
      expect(resolver.getResource('ProcessingFunction')).not.toBeNull();
      
      // Test reference resolution
      const bucketRef = resolver.resolve({ Ref: 'DataBucket' });
      expect(bucketRef.value).toBe('DataBucket');
      expect(bucketRef.isResolved).toBe(true);
      
      // Test GetAtt resolution
      const roleArn = resolver.resolve({ 'Fn::GetAtt': ['LambdaExecutionRole', 'Arn'] });
      expect(roleArn.value).toBeNull();
      expect(roleArn.isResolved).toBe(false);
      expect(roleArn.referencedResources).toContain('LambdaExecutionRole');
      
      // Test complex nested resolution
      const lambdaFunction = resolver.getResource('ProcessingFunction');
      const envVars = resolver.resolve(lambdaFunction.Properties.Environment.Variables);
      expect(envVars.isResolved).toBe(true);
      expect(envVars.referencedResources).toContain('DataBucket');
    });

    it('should handle circular references gracefully', () => {
      // This test ensures the resolver doesn't get stuck in infinite loops
      const resources = [
        createTestResource('AWS::IAM::Role', {
          AssumeRolePolicyDocument: {
            Statement: [{
              Resource: { Ref: 'LambdaFunction' }
            }]
          }
        }, 'LambdaRole'),
        createTestResource('AWS::Lambda::Function', {
          Role: { Ref: 'LambdaRole' }
        }, 'LambdaFunction')
      ];
      
      const resolver = new CloudFormationResolver(resources);
      
      // Both of these should resolve without hanging
      const roleRef = resolver.resolve({ Ref: 'LambdaRole' });
      expect(roleRef.value).toBe('LambdaRole');
      expect(roleRef.isResolved).toBe(true);
      
      const functionRef = resolver.resolve({ Ref: 'LambdaFunction' });
      expect(functionRef.value).toBe('LambdaFunction');
      expect(functionRef.isResolved).toBe(true);
    });
  });
});
