import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import EMR007Rule from '../../../../../../src/assess/scanning/security-matrix/rules/emr/007-security-group-ingress.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('EMR-007: EMR cluster security group ingress rule', () => {
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
          InstanceCount: 3,
          ...props.Instances
        },
        ...props
      }
    };
  }

  function createSecurityGroup(logicalId: string, hasOpenIngress: boolean = false): CloudFormationResource {
    const ingress = hasOpenIngress ? [
      {
        IpProtocol: 'tcp',
        FromPort: 22,
        ToPort: 22,
        CidrIp: '0.0.0.0/0'  // Open ingress
      }
    ] : [
      {
        IpProtocol: 'tcp',
        FromPort: 22,
        ToPort: 22,
        CidrIp: '10.0.0.0/8'  // Restricted ingress
      }
    ];

    return {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: logicalId,
      Properties: {
        GroupDescription: 'EMR Security Group',
        SecurityGroupIngress: ingress
      }
    };
  }

  it('passes when EMR cluster has no security groups configured', () => {
    const cluster = createEMRCluster();
    const allResources = [cluster];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).toBeNull();
  });

  it('passes when EMR cluster security groups have restricted ingress', () => {
    const cluster = createEMRCluster({
      Instances: {
        AdditionalMasterSecurityGroups: ['RestrictedSG']
      }
    });
    const securityGroup = createSecurityGroup('RestrictedSG', false);
    const allResources = [cluster, securityGroup];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).toBeNull();
  });

  it('fails when EMR cluster security group has open ingress', () => {
    const cluster = createEMRCluster({
      Instances: {
        AdditionalMasterSecurityGroups: ['OpenSG']
      }
    });
    const securityGroup = createSecurityGroup('OpenSG', true);
    const allResources = [cluster, securityGroup];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster security group allows open ingress');
    expect((result as ScanResult).fix).toContain('Remove open ingress rules (0.0.0.0/0) from security group');
  });

  it('fails when EMR managed master security group has open ingress', () => {
    const cluster = createEMRCluster({
      Instances: {
        EmrManagedMasterSecurityGroup: 'MasterSG'
      }
    });
    const securityGroup = createSecurityGroup('MasterSG', true);
    const allResources = [cluster, securityGroup];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster security group allows open ingress');
  });

  it('fails when additional slave security group has open ingress', () => {
    const cluster = createEMRCluster({
      Instances: {
        AdditionalSlaveSecurityGroups: ['SlaveSG']
      }
    });
    const securityGroup = createSecurityGroup('SlaveSG', true);
    const allResources = [cluster, securityGroup];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster security group allows open ingress');
  });

  it('passes when security group has IPv6 restricted ingress', () => {
    const cluster = createEMRCluster({
      Instances: {
        AdditionalMasterSecurityGroups: ['IPv6SG']
      }
    });
    const securityGroup: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'IPv6SG',
      Properties: {
        GroupDescription: 'IPv6 Security Group',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIpv6: '2001:db8::/32'  // Restricted IPv6
          }
        ]
      }
    };
    const allResources = [cluster, securityGroup];

    const result = EMR007Rule.evaluate(cluster, stackName, allResources);
    expect(result).toBeNull();
  });

  it('fails when allResources is not provided', () => {
    const cluster = createEMRCluster({
      Instances: {
        AdditionalMasterSecurityGroups: ['SomeSG']
      }
    });

    const result = EMR007Rule.evaluate(cluster, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('EMR cluster security group allows open ingress');
    expect((result as ScanResult).fix).toContain('Ensure security groups referenced by EMR cluster do not allow open ingress');
  });

  it('ignores non-EMR resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {
        InstanceType: 't3.micro'
      }
    };

    const result = EMR007Rule.evaluate(resource, stackName, []);
    expect(result).toBeNull();
  });
});