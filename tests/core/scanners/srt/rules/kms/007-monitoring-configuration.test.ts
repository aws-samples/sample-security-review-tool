import { describe, it, expect } from 'vitest';
import { KMS007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/kms/007-monitoring-configuration.cf.js';

describe('KMS-007: Configure monitoring infrastructure for KMS events', () => {
  const rule = new KMS007Rule();

  it('should flag KMS key without monitoring infrastructure', () => {
    const resource = {
      Type: 'AWS::KMS::Key',
      Properties: {}
    };
    const template = { Resources: { TestKey: resource } };

    const result = rule.evaluateResource('TestStack', template, resource);
    expect(result).not.toBeNull();
    expect(result?.fix).toBe('Add EventBridge rule with EventPattern source "aws.kms" and Lambda function target for KMS event monitoring. The Lambda function should have X-Ray tracing enabled. The Lambda function should have CloudWatch Alarms for the following Lambda metrics: Errors, Throttles, Duration, Invocations, ConcurrentExecutions, and DeadLetterErrors.');
  });

  it('should pass KMS key with EventBridge rule and Lambda target', () => {
    const kmsResource = {
      Type: 'AWS::KMS::Key',
      Properties: {}
    };
    const eventRuleResource = {
      Type: 'AWS::Events::Rule',
      Properties: {
        EventPattern: {
          source: ['aws.kms']
        },
        Targets: [{
          Arn: 'arn:aws:lambda:us-east-1:123456789012:function:KMSMonitor',
          Id: 'KMSTarget'
        }]
      }
    };
    const template = { 
      Resources: { 
        TestKey: kmsResource,
        TestRule: eventRuleResource
      } 
    };

    const result = rule.evaluateResource('TestStack', template, kmsResource);
    expect(result).toBeNull();
  });

  it('should flag EventBridge rule without targets', () => {
    const kmsResource = {
      Type: 'AWS::KMS::Key',
      Properties: {}
    };
    const eventRuleResource = {
      Type: 'AWS::Events::Rule',
      Properties: {
        EventPattern: {
          source: ['aws.kms']
        }
      }
    };
    const template = { 
      Resources: { 
        TestKey: kmsResource,
        TestRule: eventRuleResource
      } 
    };

    const result = rule.evaluateResource('TestStack', template, kmsResource);
    expect(result).not.toBeNull();
    expect(result?.fix).toBe('Add EventBridge rule with EventPattern source "aws.kms" and Lambda function target for KMS event monitoring. The Lambda function should have X-Ray tracing enabled. The Lambda function should have CloudWatch Alarms for the following Lambda metrics: Errors, Throttles, Duration, Invocations, ConcurrentExecutions, and DeadLetterErrors.');
  });

  it('should pass KMS key with Security Hub', () => {
    const kmsResource = {
      Type: 'AWS::KMS::Key',
      Properties: {}
    };
    const securityHubResource = {
      Type: 'AWS::SecurityHub::Hub',
      Properties: {}
    };
    const template = { 
      Resources: { 
        TestKey: kmsResource,
        TestHub: securityHubResource
      } 
    };

    const result = rule.evaluateResource('TestStack', template, kmsResource);
    expect(result).toBeNull();
  });

  it('should pass KMS key with Config rule', () => {
    const kmsResource = {
      Type: 'AWS::KMS::Key',
      Properties: {}
    };
    const configRuleResource = {
      Type: 'AWS::Config::ConfigRule',
      Properties: {
        Source: {
          Owner: 'AWS',
          SourceIdentifier: 'cmk-backing-key-rotation-enabled'
        }
      }
    };
    const template = { 
      Resources: { 
        TestKey: kmsResource,
        TestConfigRule: configRuleResource
      } 
    };

    const result = rule.evaluateResource('TestStack', template, kmsResource);
    expect(result).toBeNull();
  });

  it('should ignore non-applicable resources', () => {
    const resource = {
      Type: 'AWS::S3::Bucket',
      Properties: {}
    };

    const result = rule.evaluateResource('TestStack', { Resources: {} }, resource);
    expect(result).toBeNull();
  });

  it('should ignore non-applicable resources', () => {
    const resource = {
      Type: 'AWS::S3::Bucket',
      Properties: {}
    };

    const result = rule.evaluateResource('TestStack', { Resources: {} }, resource);
    expect(result).toBeNull();
  });

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('KMS-007');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::KMS::Key')).toBe(true);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });
});