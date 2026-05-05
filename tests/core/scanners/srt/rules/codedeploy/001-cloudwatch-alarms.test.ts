import { describe, it, expect, beforeEach } from 'vitest';
import { CodeDeploy001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/001-cloudwatch-alarms.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CODEDEPLOY-001: Implement CloudWatch alarms for CodeDeploy monitoring', () => {
  let rule: CodeDeploy001Rule;

  beforeEach(() => {
    rule = new CodeDeploy001Rule();
  });

  it('should flag application without CloudWatch alarms', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodeDeploy::Application',
      LogicalId: 'TestApp',
      Properties: {
        ApplicationName: 'MyApp'
      }
    };

    const result = rule.evaluate(resource, 'test-stack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('CodeDeploy application lacks CloudWatch alarms');
    expect(result?.fix).toContain('AWS::CloudWatch::Alarm');
    expect(result?.fix).toContain('AWS/CodeDeploy');
  });

  it('should pass application with related CloudWatch alarm', () => {
    const app: CloudFormationResource = {
      Type: 'AWS::CodeDeploy::Application',
      LogicalId: 'TestApp',
      Properties: {
        ApplicationName: 'MyApp'
      }
    };

    const alarm: CloudFormationResource = {
      Type: 'AWS::CloudWatch::Alarm',
      LogicalId: 'TestAlarm',
      Properties: {
        MetricName: 'FailedDeployments',
        Namespace: 'AWS/CodeDeploy',
        Dimensions: [{
          Name: 'ApplicationName',
          Value: 'MyApp'
        }]
      }
    };

    const result = rule.evaluate(app, 'test-stack', [app, alarm]);
    expect(result).toBeNull();
  });

  it('should pass application with alarm referencing logical ID', () => {
    const app: CloudFormationResource = {
      Type: 'AWS::CodeDeploy::Application',
      LogicalId: 'TestApp',
      Properties: {}
    };

    const alarm: CloudFormationResource = {
      Type: 'AWS::CloudWatch::Alarm',
      LogicalId: 'TestAlarm',
      Properties: {
        MetricName: 'FailedDeployments',
        Namespace: 'AWS/CodeDeploy',
        Dimensions: [{
          Name: 'ApplicationName',
          Value: { Ref: 'TestApp' }
        }]
      }
    };

    const result = rule.evaluate(app, 'test-stack', [app, alarm]);
    expect(result).toBeNull();
  });
});