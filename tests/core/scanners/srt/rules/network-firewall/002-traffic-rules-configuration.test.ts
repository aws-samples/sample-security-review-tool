import { describe, it, expect } from 'vitest';
import { NF002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/network-firewall/002-traffic-rules-configuration';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { hasIntrinsicFunction } from '../../../../../../src/assess/scanning/utils/cloudformation-intrinsic-utils';

describe('NF002Rule', () => {
  const rule = new NF002Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a firewall is not associated with a policy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          SubnetMappings: [
            { SubnetId: 'subnet-1' },
            { SubnetId: 'subnet-2' }
          ]
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::Firewall');
      expect(result?.resourceName).toBe('TestFirewall');
      expect(result?.issue).toContain('Firewall is not associated with a policy');
    });

    it('should return a finding if a firewall is not deployed in multiple subnets', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: 'arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy',
          SubnetMappings: [
            { SubnetId: 'subnet-1' }
          ]
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::Firewall');
      expect(result?.resourceName).toBe('TestFirewall');
      expect(result?.issue).toContain('Firewall is not deployed in multiple subnets');
    });

    it('should return a finding if a firewall does not have logging configured', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: 'arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy',
          SubnetMappings: [
            { SubnetId: 'subnet-1' },
            { SubnetId: 'subnet-2' }
          ]
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::Firewall');
      expect(result?.resourceName).toBe('TestFirewall');
      expect(result?.issue).toContain('Firewall logging is not configured');
    });

    it('should not return a finding for a properly configured firewall', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: 'arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy',
          SubnetMappings: [
            { SubnetId: 'subnet-1' },
            { SubnetId: 'subnet-2' }
          ],
          LoggingConfiguration: {
            LogDestinationConfigs: [
              {
                LogType: 'FLOW',
                LogDestinationType: 'CloudWatchLogs',
                LogDestination: {
                  'logGroup': 'my-log-group'
                }
              }
            ]
          }
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CloudFormation intrinsic functions for FirewallPolicyArn', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: { 'Ref': 'FirewallPolicyArn' },
          SubnetMappings: [
            { SubnetId: 'subnet-1' },
            { SubnetId: 'subnet-2' }
          ],
          LoggingConfiguration: {
            LogDestinationConfigs: [
              {
                LogType: 'FLOW',
                LogDestinationType: 'CloudWatchLogs',
                LogDestination: {
                  'logGroup': 'my-log-group'
                }
              }
            ]
          }
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
      expect(hasIntrinsicFunction(resource.Properties.FirewallPolicyArn)).toBe(true);
    });

    it('should handle CloudFormation intrinsic functions for SubnetMappings', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: 'arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy',
          SubnetMappings: { 'Fn::GetAtt': ['VPC', 'SubnetMappings'] },
          LoggingConfiguration: {
            LogDestinationConfigs: [
              {
                LogType: 'FLOW',
                LogDestinationType: 'CloudWatchLogs',
                LogDestination: {
                  'logGroup': 'my-log-group'
                }
              }
            ]
          }
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
      expect(hasIntrinsicFunction(resource.Properties.SubnetMappings)).toBe(true);
    });

    it('should handle CloudFormation intrinsic functions for LoggingConfiguration', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::Firewall',
        Properties: {
          FirewallPolicyArn: 'arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy',
          SubnetMappings: [
            { SubnetId: 'subnet-1' },
            { SubnetId: 'subnet-2' }
          ],
          LoggingConfiguration: { 'Fn::If': [
            'EnableLogging',
            {
              LogDestinationConfigs: [
                {
                  LogType: 'FLOW',
                  LogDestinationType: 'CloudWatchLogs',
                  LogDestination: {
                    'logGroup': 'my-log-group'
                  }
                }
              ]
            },
            { 'Ref': 'AWS::NoValue' }
          ]}
        },
        LogicalId: 'TestFirewall'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
      expect(hasIntrinsicFunction(resource.Properties.LoggingConfiguration)).toBe(true);
    });

    it('should return a finding if a firewall policy is not managed by Firewall Manager', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::FirewallPolicy',
        Properties: {
          FirewallPolicy: {
            StatefulRuleGroupReferences: [
              { ResourceArn: 'arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/test-group' }
            ],
            StatelessDefaultActions: ['aws:forward_to_sfe'],
            StatelessFragmentDefaultActions: ['aws:forward_to_sfe']
          },
          Tags: [
            { Key: 'Environment', Value: 'Production' }
          ]
        },
        LogicalId: 'TestFirewallPolicy'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::FirewallPolicy');
      expect(result?.resourceName).toBe('TestFirewallPolicy');
      expect(result?.issue).toContain('Firewall policy is not managed by AWS Firewall Manager');
    });

    it('should handle CloudFormation intrinsic functions for Tags', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::FirewallPolicy',
        Properties: {
          FirewallPolicy: {
            StatefulRuleGroupReferences: [
              { ResourceArn: 'arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/test-group' }
            ],
            StatelessDefaultActions: ['aws:forward_to_sfe'],
            StatelessFragmentDefaultActions: ['aws:forward_to_sfe']
          },
          Tags: { 'Fn::GetAtt': ['FMSPolicy', 'Tags'] }
        },
        LogicalId: 'TestFirewallPolicy'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull(); // Still returns a finding because we can't determine if it has FMS tags
      expect(hasIntrinsicFunction(resource.Properties.Tags)).toBe(true);
    });

    it('should handle CloudFormation intrinsic functions for tag values', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::FirewallPolicy',
        Properties: {
          FirewallPolicy: {
            StatefulRuleGroupReferences: [
              { ResourceArn: 'arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/test-group' }
            ],
            StatelessDefaultActions: ['aws:forward_to_sfe'],
            StatelessFragmentDefaultActions: ['aws:forward_to_sfe']
          },
          Tags: [
            { 
              Key: 'aws:cloudformation:stack-name', 
              Value: { 'Fn::Sub': '${AWS::StackName}-FMS-Policy' }
            }
          ]
        },
        LogicalId: 'TestFirewallPolicy'
      };

      // Add Security Hub resource to pass the Security Hub integration check
      const securityHubResource: CloudFormationResource = {
        Type: 'AWS::SecurityHub::Hub',
        Properties: {},
        LogicalId: 'SecurityHub'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource, securityHubResource]);

      // Assert
      expect(result).toBeNull(); // Should pass because the tag value contains "FMS" and Security Hub is enabled
      expect(hasIntrinsicFunction(resource.Properties.Tags[0].Value)).toBe(true);
    });

    it('should return a finding if a firewall policy does not have stateful rule groups', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::FirewallPolicy',
        Properties: {
          FirewallPolicy: {
            StatelessDefaultActions: ['aws:forward_to_sfe'],
            StatelessFragmentDefaultActions: ['aws:forward_to_sfe']
          },
          Tags: [
            { Key: 'aws:cloudformation:stack-name', Value: 'FMS-Policy' }
          ]
        },
        LogicalId: 'TestFirewallPolicy'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::FirewallPolicy');
      expect(result?.resourceName).toBe('TestFirewallPolicy');
      expect(result?.issue).toContain('Firewall policy does not have any stateful rule groups');
    });

    it('should return a finding if a stateless rule group does not have any rules', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATELESS',
          RuleGroup: {
            RulesSource: {
              StatelessRulesAndCustomActions: {
                StatelessRules: []
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Stateless rule group does not have any rules defined');
    });

    it('should return a finding if a stateless rule group has overly permissive rules', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATELESS',
          RuleGroup: {
            RulesSource: {
              StatelessRulesAndCustomActions: {
                StatelessRules: [
                  {
                    Priority: 1,
                    RuleDefinition: {
                      Actions: ['aws:pass'],
                      MatchAttributes: {
                        Sources: [
                          { AddressDefinition: '0.0.0.0/0' }
                        ],
                        Destinations: [
                          { AddressDefinition: '0.0.0.0/0' }
                        ],
                        Protocols: [0]
                      }
                    }
                  }
                ]
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Rule group contains overly permissive rules');
    });

    it('should handle CloudFormation intrinsic functions for rule definitions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATELESS',
          RuleGroup: {
            RulesSource: {
              StatelessRulesAndCustomActions: {
                StatelessRules: [
                  {
                    Priority: 1,
                    RuleDefinition: { 'Fn::GetAtt': ['RuleDefinition', 'Definition'] }
                  }
                ]
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull(); // Should pass because we can't determine if the rule is permissive
      expect(hasIntrinsicFunction(resource.Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[0].RuleDefinition)).toBe(true);
    });

    it('should handle CloudFormation intrinsic functions for address definitions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATELESS',
          RuleGroup: {
            RulesSource: {
              StatelessRulesAndCustomActions: {
                StatelessRules: [
                  {
                    Priority: 1,
                    RuleDefinition: {
                      Actions: ['aws:pass'],
                      MatchAttributes: {
                        Sources: [
                          { AddressDefinition: { 'Fn::Sub': '${VpcCidr}' } }
                        ],
                        Destinations: [
                          { AddressDefinition: { 'Fn::Sub': '${DestinationCidr}' } }
                        ],
                        Protocols: [6] // TCP
                      }
                    }
                  }
                ]
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull(); // Should pass because we can't determine if the addresses are permissive
      expect(hasIntrinsicFunction(resource.Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[0].RuleDefinition.MatchAttributes.Sources[0].AddressDefinition)).toBe(true);
    });

    it('should detect permissive patterns in CloudFormation intrinsic functions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATELESS',
          RuleGroup: {
            RulesSource: {
              StatelessRulesAndCustomActions: {
                StatelessRules: [
                  {
                    Priority: 1,
                    RuleDefinition: {
                      Actions: ['aws:pass'],
                      MatchAttributes: {
                        Sources: [
                          { AddressDefinition: { 'Fn::Sub': '0.0.0.0/0' } }
                        ],
                        Destinations: [
                          { AddressDefinition: { 'Fn::Sub': '0.0.0.0/0' } }
                        ],
                        Protocols: [0]
                      }
                    }
                  }
                ]
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Rule group contains overly permissive rules');
    });

    it('should return a finding if a stateful rule group does not have any rules defined', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {}
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Stateful rule group does not have any rules defined');
    });

    it('should return a finding if a domain list in a rule group is empty', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesSourceList: {
                GeneratedRulesType: 'ALLOWLIST',
                TargetTypes: ['HTTP_HOST']
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Domain list in rule group is empty');
    });

    it('should return a finding if a domain list contains overly permissive wildcards', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesSourceList: {
                GeneratedRulesType: 'ALLOWLIST',
                TargetTypes: ['HTTP_HOST'],
                Targets: ['*']
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Domain list contains overly permissive wildcards');
    });

    it('should handle CloudFormation intrinsic functions for domain targets', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesSourceList: {
                GeneratedRulesType: 'ALLOWLIST',
                TargetTypes: ['HTTP_HOST'],
                Targets: { 'Fn::Split': [',', { 'Fn::ImportValue': 'AllowedDomains' }] }
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull(); // Should pass because we can't determine if the domains are permissive
      expect(hasIntrinsicFunction(resource.Properties.RuleGroup.RulesSource.RulesSourceList.Targets)).toBe(true);
    });

    it('should detect wildcard patterns in CloudFormation intrinsic functions for domains', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesSourceList: {
                GeneratedRulesType: 'ALLOWLIST',
                TargetTypes: ['HTTP_HOST'],
                Targets: [
                  'example.com',
                  { 'Fn::Sub': '*' }
                ]
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::NetworkFirewall::RuleGroup');
      expect(result?.resourceName).toBe('TestRuleGroup');
      expect(result?.issue).toContain('Domain list contains overly permissive wildcards');
    });

    it('should not return a finding for a properly configured stateful rule group with domain list', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesSourceList: {
                GeneratedRulesType: 'ALLOWLIST',
                TargetTypes: ['HTTP_HOST'],
                Targets: ['example.com', 'api.example.com']
              }
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding for a properly configured stateful rule group with rules string', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::NetworkFirewall::RuleGroup',
        Properties: {
          Type: 'STATEFUL',
          RuleGroup: {
            RulesSource: {
              RulesString: 'pass tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Allowing HTTPS traffic"; sid:1;)'
            }
          }
        },
        LogicalId: 'TestRuleGroup'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for non-Network Firewall resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs14.x',
          Code: {
            S3Bucket: 'my-bucket',
            S3Key: 'my-key'
          }
        },
        LogicalId: 'TestFunction'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
