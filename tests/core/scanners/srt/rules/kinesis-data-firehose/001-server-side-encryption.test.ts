import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import KDF001Rule from '../../../../../../src/assess/scanning/security-matrix/rules/kinesis-data-firehose/001-server-side-encryption.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('KDF-001: Kinesis Data Firehose server-side encryption rule', () => {
  const stackName = 'test-stack';

  function createDeliveryStream(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::KinesisFirehose::DeliveryStream',
      LogicalId: 'TestDeliveryStream',
      Properties: {
        DeliveryStreamName: 'test-delivery-stream',
        S3DestinationConfiguration: {
          BucketARN: 'arn:aws:s3:::test-bucket',
          RoleARN: 'arn:aws:iam::123456789012:role/firehose-role'
        },
        ...props
      }
    };
  }

  it('passes when delivery stream has AWS owned CMK encryption', () => {
    const resource = createDeliveryStream({
      DeliveryStreamEncryptionConfigurationInput: {
        KeyType: 'AWS_OWNED_CMK'
      }
    });

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when delivery stream has customer managed CMK with KeyARN', () => {
    const resource = createDeliveryStream({
      DeliveryStreamEncryptionConfigurationInput: {
        KeyType: 'CUSTOMER_MANAGED_CMK',
        KeyARN: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef'
      }
    });

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when delivery stream has no encryption configuration', () => {
    const resource = createDeliveryStream();

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream does not have server-side encryption enabled');
    expect((result as ScanResult).fix).toContain('Add DeliveryStreamEncryptionConfigurationInput with KeyType');
  });

  it('fails when delivery stream has invalid KeyType', () => {
    const resource = createDeliveryStream({
      DeliveryStreamEncryptionConfigurationInput: {
        KeyType: 'INVALID_KEY_TYPE'
      }
    });

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream does not have server-side encryption enabled');
    expect((result as ScanResult).fix).toContain('Set KeyType to \'AWS_OWNED_CMK\' or \'CUSTOMER_MANAGED_CMK\'');
  });

  it('fails when delivery stream has empty KeyType', () => {
    const resource = createDeliveryStream({
      DeliveryStreamEncryptionConfigurationInput: {}
    });

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream does not have server-side encryption enabled');
    expect((result as ScanResult).fix).toContain('Set KeyType to \'AWS_OWNED_CMK\' or \'CUSTOMER_MANAGED_CMK\'');
  });

  it('fails when delivery stream uses customer managed CMK without KeyARN', () => {
    const resource = createDeliveryStream({
      DeliveryStreamEncryptionConfigurationInput: {
        KeyType: 'CUSTOMER_MANAGED_CMK'
      }
    });

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('Kinesis Data Firehose delivery stream does not have server-side encryption enabled');
    expect((result as ScanResult).fix).toContain('When using CUSTOMER_MANAGED_CMK, specify KeyARN');
  });

  it('ignores non-Firehose resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Kinesis::Stream',
      LogicalId: 'TestStream',
      Properties: {
        ShardCount: 1
      }
    };

    const result = KDF001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});