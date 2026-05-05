import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import EMR001Rule from '../../../../../../src/assess/scanning/security-matrix/rules/emr/001-private-subnet.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('EMR-001: EMR cluster private subnet rule', () => {
  const stackName = 'test-stack';

  function createEMRCluster(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::EMR::Cluster',
      LogicalId: 'TestEMRCluster',
      Properties: {
        Name: 'test-cluster',
        ReleaseLabel: 'emr-6.4.0',
        ...props
      }
    };
  }

  it('passes when EMR cluster has Ec2SubnetId configured', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetId: 'subnet-12345678',
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster has Ec2SubnetIds configured', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetIds: ['subnet-12345678', 'subnet-87654321'],
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster has both Ec2SubnetId and Ec2SubnetIds', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetId: 'subnet-12345678',
        Ec2SubnetIds: ['subnet-87654321'],
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when EMR cluster has no subnet configuration', () => {
    const resource = createEMRCluster({
      Instances: {
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster is not configured with VPC private subnet');
    expect((result as ScanResult).fix).toContain('Add Instances.Ec2SubnetId or Instances.Ec2SubnetIds');
  });

  it('fails when EMR cluster has empty Ec2SubnetIds array', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetIds: [],
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster is not configured with VPC private subnet');
  });

  it('fails when EMR cluster has no Instances configuration', () => {
    const resource = createEMRCluster();

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster is not configured with VPC private subnet');
  });

  it('ignores non-EMR resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {
        InstanceType: 't3.micro'
      }
    };

    const result = EMR001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});