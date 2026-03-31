import { describe, it, expect } from 'vitest';
import { IoT020Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/020-device-defender-audit.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT020Rule - Use IoT Device Defender to audit device fleet', () => {
  const rule = new IoT020Rule();
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

  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-020');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::Thing')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::ThingGroup')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('Device Fleet Evaluation', () => {
    it('should pass when security profiles are configured', () => {
      const thing = createIoTThing();
      const securityProfile = {
        Type: 'AWS::IoT::SecurityProfile',
        LogicalId: 'AuditProfile',
        Properties: {
          SecurityProfileName: 'audit-profile',
          Behaviors: [{ Name: 'audit-check' }]
        }
      };

      const allResources = [thing, securityProfile];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should pass when fleet metrics are configured', () => {
      const thing = createIoTThing();
      const fleetMetric = {
        Type: 'AWS::IoT::FleetMetric',
        LogicalId: 'FleetMetric',
        Properties: {
          MetricName: 'fleet-metric',
          QueryString: 'SELECT * FROM fleet'
        }
      };

      const allResources = [thing, fleetMetric];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should pass when audit Lambda function exists', () => {
      const thing = createIoTThing();
      const auditLambda = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'AuditFunction',
        Properties: {
          FunctionName: 'device-audit',
          Code: { ZipFile: 'device-defender audit code' }
        }
      };

      const allResources = [thing, auditLambda];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when no audit configuration exists', () => {
      const thing = createIoTThing();

      const result = rule.evaluate(thing, stackName, [thing]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no audit configuration found');
    });

    it('should fail when allResources is not provided', () => {
      const thing = createIoTThing();

      const result = rule.evaluate(thing, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('cannot verify Device Defender configuration');
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