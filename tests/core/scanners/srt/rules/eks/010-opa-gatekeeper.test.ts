import { describe, it, expect } from 'vitest';
import { EKS010Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/010-opa-gatekeeper.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS010Rule', () => {
  const rule = new EKS010Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding if an EKS cluster has no Gatekeeper configuration', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'TestCluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName, [resource]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('EKS cluster does not have Open Policy Agent (OPA) & Gatekeeper configured');
      });

      it('should return a finding if an EKS cluster has Gatekeeper but no OPA policies', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'TestCluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        const gatekeeperAddon: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper',
            ConfigurationValues: '{"replicas": 3}'
          },
          LogicalId: 'GatekeeperAddon'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, gatekeeperAddon]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no OPA policies found');
      });

      it('should not return a finding if an EKS cluster has Gatekeeper and OPA policies', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'TestCluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        const gatekeeperAddon: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper',
            ConfigurationValues: '{"replicas": 3}'
          },
          LogicalId: 'GatekeeperAddon'
        };

        const opaPolicy: CloudFormationResource = {
          Type: 'Custom::AWSQS-KubernetesResource',
          Properties: {
            ClusterName: 'TestCluster',
            Manifest: `
              apiVersion: templates.gatekeeper.sh/v1beta1
              kind: ConstraintTemplate
              metadata:
                name: k8srequiredlabels
              spec:
                crd:
                  spec:
                    names:
                      kind: K8sRequiredLabels
            `
          },
          LogicalId: 'OpaPolicy'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, gatekeeperAddon, opaPolicy]);

        // Assert
        expect(result).toBeNull();
      });

      it('should recognize Helm chart resources as valid Gatekeeper configuration', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'TestCluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        const helmChart: CloudFormationResource = {
          Type: 'Custom::HelmChart',
          Properties: {
            ClusterName: 'TestCluster',
            Chart: 'gatekeeper',
            Values: '{"replicas": 3}'
          },
          LogicalId: 'GatekeeperHelmChart'
        };

        const opaPolicy: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            ClusterName: 'TestCluster',
            Manifest: `
              apiVersion: constraints.gatekeeper.sh/v1beta1
              kind: K8sRequiredLabels
              metadata:
                name: require-team-label
              spec:
                match:
                  kinds:
                    - apiGroups: [""]
                      kinds: ["Namespace"]
                parameters:
                  labels: ["team"]
            `
          },
          LogicalId: 'OpaConstraint'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, helmChart, opaPolicy]);

        // Assert
        expect(result).toBeNull();
      });

      it('should recognize custom resources as valid OPA policies', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'TestCluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        const gatekeeperAddon: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper',
            ConfigurationValues: '{"replicas": 3}'
          },
          LogicalId: 'GatekeeperAddon'
        };

        const customConstraint: CloudFormationResource = {
          Type: 'Custom::OPAConstraint',
          Properties: {
            ClusterName: 'TestCluster',
            ConstraintKind: 'K8sPSPCapabilities',
            Parameters: {
              allowedCapabilities: ['NET_BIND_SERVICE']
            }
          },
          LogicalId: 'CustomConstraint'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, gatekeeperAddon, customConstraint]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in cluster name', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: { 'Fn::Join': ['-', ['test', 'cluster']] },
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('EKS cluster does not have Open Policy Agent (OPA) & Gatekeeper configured');
      });
    });

    describe('EKS Addon tests', () => {
      it('should return a finding for a Gatekeeper addon without configuration', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper'
            // Missing ConfigurationValues
          },
          LogicalId: 'GatekeeperAddon'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Addon');
        expect(result?.resourceName).toBe('GatekeeperAddon');
        expect(result?.issue).toContain('Gatekeeper addon without configuration');
      });

      it('should not return a finding for a Gatekeeper addon with configuration', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper',
            ConfigurationValues: '{"replicas": 3}'
          },
          LogicalId: 'GatekeeperAddon'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a non-Gatekeeper addon', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'aws-ebs-csi-driver'
          },
          LogicalId: 'EbsDriverAddon'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in AddonName', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: { Ref: 'AddonName' }
          },
          LogicalId: 'GatekeeperAddon'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Cannot determine if it's a Gatekeeper addon
      });

      it('should handle intrinsic functions in ConfigurationValues', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Addon',
          Properties: {
            ClusterName: 'TestCluster',
            AddonName: 'gatekeeper',
            ConfigurationValues: { 'Fn::Join': ['', ['{"replicas":', { Ref: 'Replicas' }, '}' ]] }
          },
          LogicalId: 'GatekeeperAddon'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // ConfigurationValues is present, even if it's an intrinsic function
      });
    });

    it('should return null for non-relevant resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
