import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import EMR006Rule from '../../../../../../src/assess/scanning/security-matrix/rules/emr/006-authentication.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('EMR-006: EMR cluster authentication rule', () => {
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

  it('passes when EMR cluster has EC2 Key Pair configured', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetId: 'subnet-12345678',
        Ec2KeyName: 'my-key-pair',
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster has Kerberos authentication configured', () => {
    const resource = createEMRCluster({
      KerberosAttributes: {
        Realm: 'EXAMPLE.COM',
        KdcAdminPassword: 'MySecurePassword123!',
        CrossRealmTrustPrincipalPassword: 'MyTrustPassword123!'
      }
    });

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster has both EC2 Key Pair and Kerberos configured', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetId: 'subnet-12345678',
        Ec2KeyName: 'my-key-pair',
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      },
      KerberosAttributes: {
        Realm: 'EXAMPLE.COM',
        KdcAdminPassword: 'MySecurePassword123!'
      }
    });

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when EMR cluster has no authentication configured', () => {
    const resource = createEMRCluster();

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have authentication configured');
    expect((result as ScanResult).fix).toContain('Add Instances.Ec2KeyName for SSH key authentication or KerberosAttributes');
  });

  it('fails when EMR cluster has empty Ec2KeyName', () => {
    const resource = createEMRCluster({
      Instances: {
        Ec2SubnetId: 'subnet-12345678',
        Ec2KeyName: '',
        MasterInstanceType: 'm5.xlarge',
        SlaveInstanceType: 'm5.large',
        InstanceCount: 3
      }
    });

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster does not have authentication configured');
  });

  it('passes when EMR cluster has minimal Kerberos configuration', () => {
    const resource = createEMRCluster({
      KerberosAttributes: {
        Realm: 'EXAMPLE.COM'
      }
    });

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('ignores non-EMR resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {
        InstanceType: 't3.micro'
      }
    };

    const result = EMR006Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});