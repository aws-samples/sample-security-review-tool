import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import EMR002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/emr/002-s3-logging.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('EMR-002: EMR cluster S3 logging rule', () => {
  const stackName = 'test-stack';

  function createEMRCluster(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::EMR::Cluster',
      LogicalId: 'TestEMRCluster',
      Properties: {
        Name: 'test-cluster',
        ReleaseLabel: 'emr-6.4.0',
        Instances: {
          Ec2SubnetId: 'subnet-12345678',
          MasterInstanceType: 'm5.xlarge',
          SlaveInstanceType: 'm5.large',
          InstanceCount: 3
        },
        ...props
      }
    };
  }

  it('passes when EMR cluster has S3 LogUri configured', () => {
    const resource = createEMRCluster({
      LogUri: 's3://my-emr-logs-bucket/logs/'
    });

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster has S3 LogUri with subdirectories', () => {
    const resource = createEMRCluster({
      LogUri: 's3://company-logs/emr/production/cluster-logs/'
    });

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when EMR cluster has no LogUri', () => {
    const resource = createEMRCluster();

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have S3 logging configured');
    expect((result as ScanResult).fix).toContain('Add LogUri property with S3 path');
  });

  it('fails when EMR cluster has empty LogUri', () => {
    const resource = createEMRCluster({
      LogUri: ''
    });

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have S3 logging configured');
  });

  it('fails when EMR cluster has non-S3 LogUri', () => {
    const resource = createEMRCluster({
      LogUri: 'hdfs://namenode:9000/logs/'
    });

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have S3 logging configured');
    expect((result as ScanResult).fix).toContain('Add LogUri property with S3 path');
  });

  it('fails when EMR cluster has local file system LogUri', () => {
    const resource = createEMRCluster({
      LogUri: '/var/log/emr/'
    });

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have S3 logging configured');
  });

  it('ignores non-EMR resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {
        InstanceType: 't3.micro'
      }
    };

    const result = EMR002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});