import { describe, it, expect } from 'vitest';
import { EKS015Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/015-non-root-user.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS015Rule', () => {
  const rule = new EKS015Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding with general guidance for an EKS cluster', () => {
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
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('general guidance');
      });
    });

    describe('Kubernetes Resource tests with string manifests', () => {
      it('should return a finding for a Kubernetes resource with no security context', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::AWSQS-KubernetesResource',
          Properties: {
            Manifest: `
              apiVersion: v1
              kind: Pod
              metadata:
                name: test-pod
              spec:
                containers:
                - name: test-container
                  image: nginx:latest
            `
          },
          LogicalId: 'TestPod'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('Custom::AWSQS-KubernetesResource');
        expect(result?.resourceName).toBe('TestPod');
        expect(result?.issue).toContain('no security context with runAsNonRoot found in manifest');
      });

      it('should not return a finding for a Kubernetes resource with runAsNonRoot: true', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::AWSQS-KubernetesResource',
          Properties: {
            Manifest: `
              apiVersion: v1
              kind: Pod
              metadata:
                name: test-pod
              spec:
                securityContext:
                  runAsNonRoot: true
                containers:
                - name: test-container
                  image: nginx:latest
            `
          },
          LogicalId: 'TestPod'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a Kubernetes resource with runAsUser > 0', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::AWSQS-KubernetesResource',
          Properties: {
            Manifest: `
              apiVersion: v1
              kind: Pod
              metadata:
                name: test-pod
              spec:
                securityContext:
                  runAsUser: 1000
                containers:
                - name: test-container
                  image: nginx:latest
            `
          },
          LogicalId: 'TestPod'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a non-Pod Kubernetes resource', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::AWSQS-KubernetesResource',
          Properties: {
            Manifest: `
              apiVersion: v1
              kind: ConfigMap
              metadata:
                name: test-configmap
              data:
                key1: value1
                key2: value2
            `
          },
          LogicalId: 'TestConfigMap'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('Kubernetes Resource tests with JSON manifests', () => {
      it('should return a finding for a Pod with no security context', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'v1',
              kind: 'Pod',
              metadata: {
                name: 'test-pod'
              },
              spec: {
                containers: [
                  {
                    name: 'test-container',
                    image: 'nginx:latest'
                  }
                ]
              }
            }
          },
          LogicalId: 'TestPod'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('Custom::KubernetesResource');
        expect(result?.resourceName).toBe('TestPod');
        expect(result?.issue).toContain('EKS cluster applications may be running as root user');
      });

      it('should return a finding for a Deployment with containers without security context', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata: {
                name: 'test-deployment'
              },
              spec: {
                replicas: 3,
                selector: {
                  matchLabels: {
                    app: 'test'
                  }
                },
                template: {
                  metadata: {
                    labels: {
                      app: 'test'
                    }
                  },
                  spec: {
                    containers: [
                      {
                        name: 'test-container',
                        image: 'nginx:latest'
                      }
                    ]
                  }
                }
              }
            }
          },
          LogicalId: 'TestDeployment'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('Custom::KubernetesResource');
        expect(result?.resourceName).toBe('TestDeployment');
        expect(result?.issue).toContain('EKS cluster applications may be running as root user');
      });

      it('should not return a finding for a Deployment with pod-level security context', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata: {
                name: 'test-deployment'
              },
              spec: {
                replicas: 3,
                selector: {
                  matchLabels: {
                    app: 'test'
                  }
                },
                template: {
                  metadata: {
                    labels: {
                      app: 'test'
                    }
                  },
                  spec: {
                    securityContext: {
                      runAsNonRoot: true
                    },
                    containers: [
                      {
                        name: 'test-container',
                        image: 'nginx:latest'
                      }
                    ]
                  }
                }
              }
            }
          },
          LogicalId: 'TestDeployment'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a Deployment with container-level security contexts', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata: {
                name: 'test-deployment'
              },
              spec: {
                replicas: 3,
                selector: {
                  matchLabels: {
                    app: 'test'
                  }
                },
                template: {
                  metadata: {
                    labels: {
                      app: 'test'
                    }
                  },
                  spec: {
                    containers: [
                      {
                        name: 'test-container-1',
                        image: 'nginx:latest',
                        securityContext: {
                          runAsNonRoot: true
                        }
                      },
                      {
                        name: 'test-container-2',
                        image: 'redis:latest',
                        securityContext: {
                          runAsUser: 1000
                        }
                      }
                    ]
                  }
                }
              }
            }
          },
          LogicalId: 'TestDeployment'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should return a finding if some containers have security context but others do not', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata: {
                name: 'test-deployment'
              },
              spec: {
                replicas: 3,
                selector: {
                  matchLabels: {
                    app: 'test'
                  }
                },
                template: {
                  metadata: {
                    labels: {
                      app: 'test'
                    }
                  },
                  spec: {
                    containers: [
                      {
                        name: 'test-container-1',
                        image: 'nginx:latest',
                        securityContext: {
                          runAsNonRoot: true
                        }
                      },
                      {
                        name: 'test-container-2',
                        image: 'redis:latest'
                        // Missing security context
                      }
                    ]
                  }
                }
              }
            }
          },
          LogicalId: 'TestDeployment'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('Custom::KubernetesResource');
        expect(result?.resourceName).toBe('TestDeployment');
        expect(result?.issue).toContain('containers without non-root security context');
      });

      it('should handle CronJob resources correctly', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'batch/v1',
              kind: 'CronJob',
              metadata: {
                name: 'test-cronjob'
              },
              spec: {
                schedule: '*/5 * * * *',
                jobTemplate: {
                  spec: {
                    template: {
                      spec: {
                        securityContext: {
                          runAsUser: 1000
                        },
                        containers: [
                          {
                            name: 'test-container',
                            image: 'busybox:latest',
                            command: ['echo', 'Hello World']
                          }
                        ],
                        restartPolicy: 'OnFailure'
                      }
                    }
                  }
                }
              }
            }
          },
          LogicalId: 'TestCronJob'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle StatefulSet resources correctly', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'Custom::KubernetesResource',
          Properties: {
            Manifest: {
              apiVersion: 'apps/v1',
              kind: 'StatefulSet',
              metadata: {
                name: 'test-statefulset'
              },
              spec: {
                serviceName: 'test',
                replicas: 3,
                selector: {
                  matchLabels: {
                    app: 'test'
                  }
                },
                template: {
                  metadata: {
                    labels: {
                      app: 'test'
                    }
                  },
                  spec: {
                    containers: [
                      {
                        name: 'test-container',
                        image: 'nginx:latest',
                        securityContext: {
                          runAsUser: 0 // Root user
                        }
                      }
                    ]
                  }
                }
              }
            }
          },
          LogicalId: 'TestStatefulSet'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('Custom::KubernetesResource');
        expect(result?.resourceName).toBe('TestStatefulSet');
        expect(result?.issue).toContain('containers without non-root security context');
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
