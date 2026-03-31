import { describe, it, expect } from 'vitest';
import { IoT030Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/030-device-defender-monitoring.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT030Rule - Device Defender Monitoring', () => {
  const rule = new IoT030Rule();
  const stackName = 'test-stack';

  // Helper functions
  function createSecurityProfile(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::IoT::SecurityProfile',
      LogicalId: props.LogicalId || 'TestSecurityProfile',
      Properties: {
        SecurityProfileName: 'test-profile',
        ...props
      }
    };
  }

  function createIoTThing(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::IoT::Thing',
      LogicalId: props.LogicalId || 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        ...props
      }
    };
  }
  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-030');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::SecurityProfile')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Thing')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::ThingGroup')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Policy')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::TopicRule')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('Security Profile Evaluation', () => {
    it('should pass when security profile has proper behaviors and alert targets', () => {
      const resource = createSecurityProfile({
        Behaviors: [
          { Name: 'authorization-failures', Metric: 'aws:num-authorization-failures' },
          { Name: 'connection-attempts', Metric: 'aws:num-connection-attempts' },
          { Name: 'message-size', Metric: 'aws:message-byte-size' }
        ],
        AlertTargets: {
          SNS: { AlertTargetArn: 'arn:aws:sns:us-east-1:123456789012:security-alerts' }
        },
        AdditionalMetricsToRetain: ['aws:num-messages-sent']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should fail when security profile has no behaviors', () => {
      const resource = createSecurityProfile({
        AlertTargets: {
          SNS: { AlertTargetArn: 'arn:aws:sns:us-east-1:123456789012:security-alerts' }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no security behaviors defined');
    });

    it('should fail when security profile has no alert targets', () => {
      const resource = createSecurityProfile({
        Behaviors: [
          { Name: 'authorization-failures', Metric: 'aws:num-authorization-failures' },
          { Name: 'connection-attempts', Metric: 'aws:num-connection-attempts' },
          { Name: 'message-size', Metric: 'aws:message-byte-size' }
        ],
        AdditionalMetricsToRetain: ['aws:num-messages-sent']
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no alert targets configured');
    });

    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::IoT::SecurityProfile',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('IoT Thing Evaluation', () => {
    it('should pass when thing is associated with security profile via Ref', () => {
      const thingResource = createIoTThing();
      const securityProfile = createSecurityProfile({
        Targets: [{ Ref: 'TestThing' }],
        Behaviors: [{ Name: 'auth-failures' }],
        AlertTargets: { SNS: { AlertTargetArn: 'arn:aws:sns:us-east-1:123456789012:alerts' } }
      });

      const allResources = [thingResource, securityProfile];
      const result = rule.evaluate(thingResource, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when thing has no associated security profile', () => {
      const thingResource = createIoTThing();

      const result = rule.evaluate(thingResource, stackName, [thingResource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no security profile targets TestThing');
    });

    it('should fail when allResources is not provided', () => {
      const thingResource = createIoTThing();

      const result = rule.evaluate(thingResource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('cannot verify security profile association');
    });

    it('should handle security profile with string targets', () => {
      const thingResource = createIoTThing();
      const securityProfile = createSecurityProfile({
        Targets: ['TestThing'],
        Behaviors: [{ Name: 'auth-failures' }],
        AlertTargets: { SNS: { AlertTargetArn: 'arn:aws:sns:us-east-1:123456789012:alerts' } }
      });

      const allResources = [thingResource, securityProfile];
      const result = rule.evaluate(thingResource, stackName, allResources);
      expect(result).toBeNull();
    });
  });

  describe('IoT Policy Evaluation', () => {
    it('should pass when policy has Device Defender permissions', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyName: 'test-policy',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['iot:Publish'],
                Resource: ['arn:aws:iot:*:*:topic/$aws/things/*/defender/*']
              }
            ]
          }
        }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should fail when policy lacks Device Defender permissions', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyName: 'test-policy',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['iot:Connect'],
                Resource: ['*']
              }
            ]
          }
        }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('policy missing Device Defender permissions');
    });
  });

  describe('Topic Rule Evaluation', () => {
    it('should pass when security topic rule has alert actions', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IoT::TopicRule',
        LogicalId: 'TestTopicRule',
        Properties: {
          RuleName: 'security-alert-rule',
          TopicRulePayload: {
            Sql: "SELECT * FROM 'topic/security/violation'",
            Actions: [
              {
                sns: {
                  targetArn: 'arn:aws:sns:us-east-1:123456789012:security-alerts',
                  roleArn: 'arn:aws:iam::123456789012:role/IoTRole'
                }
              }
            ]
          }
        }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should fail when security topic rule has no alert actions', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IoT::TopicRule',
        LogicalId: 'TestTopicRule',
        Properties: {
          RuleName: 'security-alert-rule',
          TopicRulePayload: {
            Sql: "SELECT * FROM 'topic/security/violation'",
            Actions: []
          }
        }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('security topic rule missing alert actions');
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        LogicalId: 'TestBucket',
        Properties: { BucketName: 'my-bucket' }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle security profile with GetAtt targets', () => {
      const thingResource = createIoTThing();
      const securityProfile = createSecurityProfile({
        Targets: [{ 'Fn::GetAtt': ['TestThing', 'Arn'] }],
        Behaviors: [{ Name: 'auth-failures' }],
        AlertTargets: { SNS: { AlertTargetArn: 'arn:aws:sns:us-east-1:123456789012:alerts' } }
      });

      const allResources = [thingResource, securityProfile];
      const result = rule.evaluate(thingResource, stackName, allResources);
      expect(result).toBeNull();
    });
  });
});