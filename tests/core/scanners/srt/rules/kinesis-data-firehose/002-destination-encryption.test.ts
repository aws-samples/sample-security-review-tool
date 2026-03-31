import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import KDF002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/kinesis-data-firehose/002-destination-encryption.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('KDF-002: Kinesis Data Firehose destination encryption rule', () => {
  const stackName = 'test-stack';

  function createDeliveryStream(destinationConfig: any): CloudFormationResource {
    return {
      Type: 'AWS::KinesisFirehose::DeliveryStream',
      LogicalId: 'TestDeliveryStream',
      Properties: {
        DeliveryStreamName: 'test-delivery-stream',
        ...destinationConfig
      }
    };
  }

  describe('S3 Destination', () => {
    it('passes when S3 destination has KMS encryption configured', () => {
      const resource = createDeliveryStream({
        S3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          EncryptionConfiguration: {
            KMSEncryptionConfig: {
              AWSKMSKeyARN: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef'
            }
          }
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('passes when ExtendedS3 destination has KMS encryption configured', () => {
      const resource = createDeliveryStream({
        ExtendedS3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          EncryptionConfiguration: {
            KMSEncryptionConfig: {
              AWSKMSKeyARN: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef'
            }
          }
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when S3 destination has no encryption configuration', () => {
      const resource = createDeliveryStream({
        S3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role'
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream destination does not have encryption enabled');
      expect((result as ScanResult).fix).toContain('Add EncryptionConfiguration to S3DestinationConfiguration');
    });

    it('fails when S3 destination has NoEncryptionConfig', () => {
      const resource = createDeliveryStream({
        S3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          EncryptionConfiguration: {
            NoEncryptionConfig: {}
          }
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream destination does not have encryption enabled');
      expect((result as ScanResult).fix).toContain('Remove NoEncryptionConfig and add KMSEncryptionConfig');
    });

    it('fails when S3 destination has empty encryption configuration', () => {
      const resource = createDeliveryStream({
        S3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          EncryptionConfiguration: {}
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream destination does not have encryption enabled');
      expect((result as ScanResult).fix).toContain('Add KMSEncryptionConfig with AWSKMSKeyARN');
    });
  });

  describe('Redshift Destination', () => {
    it('passes when Redshift destination has encrypted S3 configuration', () => {
      const resource = createDeliveryStream({
        RedshiftDestinationConfiguration: {
          ClusterJDBCURL: 'jdbc:redshift://test-cluster.abc123.us-east-1.redshift.amazonaws.com:5439/test',
          Username: 'testuser',
          Password: 'testpass',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          S3Configuration: {
            BucketARN: 'arn:aws:s3:::test-bucket',
            RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
            EncryptionConfiguration: {
              KMSEncryptionConfig: {
                AWSKMSKeyARN: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef'
              }
            }
          }
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when Redshift destination has unencrypted S3 configuration', () => {
      const resource = createDeliveryStream({
        RedshiftDestinationConfiguration: {
          ClusterJDBCURL: 'jdbc:redshift://test-cluster.abc123.us-east-1.redshift.amazonaws.com:5439/test',
          Username: 'testuser',
          Password: 'testpass',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
          S3Configuration: {
            BucketARN: 'arn:aws:s3:::test-bucket',
            RoleARN: 'arn:aws:iam::123456789012:role/firehose-role'
          }
        }
      });

      const result = KDF002Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream destination does not have encryption enabled');
    });
  });

  it('passes when delivery stream has no supported destination configuration', () => {
    const resource = createDeliveryStream({
      HttpEndpointDestinationConfiguration: {
        EndpointConfiguration: {
          Url: 'https://example.com/webhook'
        }
      }
    });

    const result = KDF002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('ignores non-Firehose resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Kinesis::Stream',
      LogicalId: 'TestStream',
      Properties: {
        ShardCount: 1
      }
    };

    const result = KDF002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});