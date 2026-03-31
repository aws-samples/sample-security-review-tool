import { describe, it, expect } from 'vitest';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import ATH002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/athena/002-encryption-in-transit';
import { Template } from 'cloudform-types';

describe('ATH-002: Athena encryption in transit rule', () => {
  const stackName = 'test-stack';

  function createTemplate(workGroupConfig: any, bucketPolicyConfig?: any): Template {
    const resources: Record<string, Resource> = {
      TestWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: workGroupConfig
      }
    };

    if (bucketPolicyConfig) {
      resources.TestBucketPolicy = {
        Type: 'AWS::S3::BucketPolicy',
        Properties: bucketPolicyConfig
      };
    }

    return { Resources: resources };
  }

  function createWorkGroupConfig(outputLocation?: string | object) {
    if (outputLocation === undefined) {
      return { Name: 'test-workgroup' };
    }
    return {
      Name: 'test-workgroup',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: outputLocation
        }
      }
    };
  }

  function createBucketPolicyConfig(bucketName: string | object, hasSecureTransport: boolean = true) {
    const statements: any[] = [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: `arn:aws:s3:::athena-results-bucket/*`
      }
    ];

    if (hasSecureTransport) {
      statements.push({
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: [
          `arn:aws:s3:::athena-results-bucket`,
          `arn:aws:s3:::athena-results-bucket/*`
        ],
        Condition: {
          Bool: {
            'aws:SecureTransport': 'false'
          }
        }
      });
    }

    return {
      Bucket: bucketName,
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: statements
      }
    };
  }

  describe('evaluateResource', () => {
    it('should pass when WorkGroup uses S3 bucket with secure transport policy', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://athena-results-bucket/results/'),
        createBucketPolicyConfig('athena-results-bucket', true)
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).toBeNull();
    });

    it('should fail when WorkGroup uses S3 bucket without secure transport policy', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://athena-results-bucket/results/'),
        createBucketPolicyConfig('athena-results-bucket', false)
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
      expect(result?.priority).toBe('HIGH');
      expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
      expect(result?.fix).toContain('athena-results-bucket');
      expect(result?.fix).toContain('aws:SecureTransport');
    });

    it('should fail when WorkGroup uses S3 bucket with no bucket policy', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://athena-results-bucket/results/')
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
      expect(result?.fix).toContain('athena-results-bucket');
    });

    it('should fail when OutputLocation is undefined', () => {
      const template = createTemplate(createWorkGroupConfig(undefined));

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
    });

    it('should fail when OutputLocation is not an S3 URL', () => {
      const template = createTemplate(
        createWorkGroupConfig('hdfs://some-other-location/')
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
    });

    it('should fail when OutputLocation is an unresolved intrinsic function', () => {
      const template = createTemplate(
        createWorkGroupConfig({ Ref: 'SomeBucket' })
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
      expect(result?.fix).toContain('Unable to validate OutputLocation');
    });

    it('should fail when OutputLocation is Fn::GetAtt', () => {
      const template = createTemplate(
        createWorkGroupConfig({ 'Fn::GetAtt': ['MyBucket', 'Arn'] })
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
      expect(result?.fix).toContain('Unable to validate OutputLocation');
    });

    it('should pass when bucket policy references bucket with Ref', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://athena-results-bucket/results/'),
        createBucketPolicyConfig({ Ref: 'athena-results-bucket' }, true)
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).toBeNull();
    });

    it('should extract bucket name correctly from S3 URL with path', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://my-athena-bucket/path/to/results/'),
        createBucketPolicyConfig('my-athena-bucket', true)
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).toBeNull();
    });

    it('should extract bucket name correctly from S3 URL without trailing slash', () => {
      const template = createTemplate(
        createWorkGroupConfig('s3://my-athena-bucket'),
        createBucketPolicyConfig('my-athena-bucket', true)
      );

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).toBeNull();
    });

    it('should return null for non-Athena resources', () => {
      const template: Template = {
        Resources: {
          TestBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: 'test-bucket'
            }
          }
        }
      };

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should verify SecureTransport condition is exactly false string', () => {
      const template: Template = {
        Resources: {
          TestWorkGroup: {
            Type: 'AWS::Athena::WorkGroup',
            Properties: createWorkGroupConfig('s3://athena-results-bucket/results/')
          },
          TestBucketPolicy: {
            Type: 'AWS::S3::BucketPolicy',
            Properties: {
              Bucket: 'athena-results-bucket',
              PolicyDocument: {
                Statement: [
                  {
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 's3:*',
                    Resource: '*',
                    Condition: {
                      Bool: {
                        'aws:SecureTransport': true  // Wrong value - should be 'false'
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      };

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('ATH-002');
    });

    it('should handle PolicyDocument with Statement array', () => {
      const template: Template = {
        Resources: {
          TestWorkGroup: {
            Type: 'AWS::Athena::WorkGroup',
            Properties: createWorkGroupConfig('s3://athena-results-bucket/results/')
          },
          TestBucketPolicy: {
            Type: 'AWS::S3::BucketPolicy',
            Properties: {
              Bucket: 'athena-results-bucket',
              PolicyDocument: {
                Statement: [
                  {
                    Effect: 'Allow',
                    Principal: '*',
                    Action: 's3:GetObject',
                    Resource: '*'
                  },
                  {
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 's3:*',
                    Resource: '*',
                    Condition: {
                      Bool: {
                        'aws:SecureTransport': 'false'
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      };

      const result = ATH002Rule.evaluateResource(stackName, template, template.Resources!.TestWorkGroup);
      expect(result).toBeNull();
    });
  });
});
