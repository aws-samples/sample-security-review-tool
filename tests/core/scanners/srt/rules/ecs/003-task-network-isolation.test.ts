import { describe, test, expect, beforeEach } from 'vitest';
import { ECS003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/003-task-network-isolation.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECS003Rule', () => {
  let rule: ECS003Rule;

  beforeEach(() => {
    rule = new ECS003Rule();
  });

  test('should have correct rule properties', () => {
    expect(rule.id).toBe('ECS-003');
    expect(rule.priority).toBe('HIGH');
  });

  test('should apply only to ECS TaskDefinition resources', () => {
    expect(rule.appliesTo('AWS::ECS::TaskDefinition')).toBe(true);
    expect(rule.appliesTo('AWS::ECS::Service')).toBe(false);
    expect(rule.appliesTo('AWS::ECS::Cluster')).toBe(false);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });

  test('should return null for non-TaskDefinition resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      Properties: {},
      LogicalId: 'TestBucket'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should return null when no allResources parameter is provided', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc'
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag TaskDefinition with non-awsvpc network mode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'bridge',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain("Use 'awsvpc' network mode");
  });

  test('should flag TaskDefinition with fixed host ports', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: 80
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Use dynamic port mapping');
  });

  test('should not flag TaskDefinition with dynamic port mapping (HostPort: 0)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: 0
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should not flag TaskDefinition with omitted HostPort', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should not flag TaskDefinition with no container definitions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc'
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should not flag TaskDefinition with empty container definitions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: []
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in NetworkMode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: { 'Fn::Sub': 'awsvpc' },
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in HostPort', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: { 'Ref': 'HostPort' }
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle Fn::If in HostPort with fixed port in true branch', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: { 'Fn::If': ['UseFixedPort', 8080, 0] }
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Use dynamic port mapping');
  });

  test('should not flag Fn::If in HostPort with dynamic ports in both branches', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: { 'Fn::If': ['UseDynamicPort', 0, 0] }
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should flag TaskDefinition with string HostPort', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: '8080'
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Use dynamic port mapping');
  });

  test('should not flag TaskDefinition with string HostPort of 0', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: '0'
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should not flag properly configured TaskDefinition', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [
          {
            Name: 'web',
            Image: 'nginx',
            Essential: true,
            PortMappings: [
              {
                ContainerPort: 80,
                HostPort: 0,
                Protocol: 'tcp'
              }
            ]
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });
});
