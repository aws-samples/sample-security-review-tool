import { describe, it, expect, beforeEach } from 'vitest';
import { Batch001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/batch/001-secure-security-groups.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('BATCH-001: Use secure security groups for Batch compute environments', () => {
  let rule: Batch001Rule;

  beforeEach(() => {
    rule = new Batch001Rule();
  });

  it('should flag compute environment without security groups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Batch::ComputeEnvironment',
      LogicalId: 'TestComputeEnv',
      Properties: {
        ComputeResources: {}
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Batch compute environment uses overly permissive security groups');
    expect(result?.fix).toContain('"SecurityGroupIds": [{ "Ref": "YourSecurityGroupLogicalId" }]');
  });

  it('should flag compute environment with overly permissive security group', () => {
    const computeEnv: CloudFormationResource = {
      Type: 'AWS::Batch::ComputeEnvironment',
      LogicalId: 'TestComputeEnv',
      Properties: {
        ComputeResources: {
          SecurityGroupIds: ['TestSG']
        }
      }
    };

    const sg: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSG',
      Properties: {
        SecurityGroupIngress: [{
          CidrIp: '0.0.0.0/0',
          FromPort: 0,
          ToPort: 65535,
          IpProtocol: 'tcp'
        }]
      }
    };

    const result = rule.evaluate(computeEnv, 'test-stack', [computeEnv, sg]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Batch compute environment uses overly permissive security groups');
    expect(result?.fix).toContain('change "CidrIp": "0.0.0.0/0" to specific IP');
    expect(result?.fix).toContain('"FromPort": 22, "ToPort": 22');
  });

  it('should pass compute environment with properly configured security group', () => {
    const computeEnv: CloudFormationResource = {
      Type: 'AWS::Batch::ComputeEnvironment',
      LogicalId: 'TestComputeEnv',
      Properties: {
        ComputeResources: {
          SecurityGroupIds: ['TestSG']
        }
      }
    };

    const sg: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSG',
      Properties: {
        SecurityGroupIngress: [{
          CidrIp: '10.0.0.0/8',
          FromPort: 80,
          ToPort: 80,
          IpProtocol: 'tcp'
        }]
      }
    };

    const result = rule.evaluate(computeEnv, 'test-stack', [computeEnv, sg]);
    expect(result).toBeNull();
  });
});