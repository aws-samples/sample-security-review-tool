import { describe, it, expect } from 'vitest';
import { IoT019Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/019-monitoring-alarms.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT019Rule - Monitor and set alarms on exceptional IoT resource usage', () => {
  const rule = new IoT019Rule();
  const stackName = 'test-stack';

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

  function createCloudWatchAlarm(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::CloudWatch::Alarm',
      LogicalId: props.LogicalId || 'TestAlarm',
      Properties: {
        AlarmName: 'test-alarm',
        MetricName: 'TestMetric',
        Namespace: 'AWS/IoT',
        Statistic: 'Sum',
        Period: 300,
        EvaluationPeriods: 1,
        Threshold: 100,
        ComparisonOperator: 'GreaterThanThreshold',
        ...props
      }
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-019');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::Thing')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::ThingGroup')).toBe(true);
      expect(rule.appliesTo('AWS::IoTSiteWise::Gateway')).toBe(true);
      expect(rule.appliesTo('AWS::IoTSiteWise::Portal')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('IoT Thing Evaluation', () => {
    it('should pass when thing has alarms and ownership', () => {
      const thing = createIoTThing({
        Tags: [{ Key: 'Owner', Value: 'team@example.com' }]
      });
      const alarm = createCloudWatchAlarm({
        Dimensions: [{ Name: 'ThingName', Value: { Ref: 'TestThing' } }]
      });
      const snsTopic = {
        Type: 'AWS::SNS::Topic',
        LogicalId: 'AlertTopic',
        Properties: { TopicName: 'iot-alerts' }
      };

      const allResources = [thing, alarm, snsTopic];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when thing has no alarms', () => {
      const thing = createIoTThing({
        Tags: [{ Key: 'Owner', Value: 'team@example.com' }]
      });

      const result = rule.evaluate(thing, stackName, [thing]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no CloudWatch alarms configured');
    });

    it('should fail when thing has no ownership', () => {
      const thing = createIoTThing();
      const alarm = createCloudWatchAlarm({
        Dimensions: [{ Name: 'ThingName', Value: { Ref: 'TestThing' } }]
      });

      const allResources = [thing, alarm];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no owner or notification target assigned');
    });

    it('should fail when allResources is not provided', () => {
      const thing = createIoTThing();

      const result = rule.evaluate(thing, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('cannot verify monitoring configuration');
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

    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});