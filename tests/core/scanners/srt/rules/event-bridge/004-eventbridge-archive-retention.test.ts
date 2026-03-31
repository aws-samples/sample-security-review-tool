import { describe, it, expect } from 'vitest';
import { Evb004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/event-bridge/004-eventbridge-archive-retention.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Evb004Rule', () => {
  const rule = new Evb004Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::Events::Archive resource type', () => {
      expect(rule.appliesTo('AWS::Events::Archive')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::Events::Rule')).toBe(false);
      expect(rule.appliesTo('AWS::Events::EventBus')).toBe(false);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for unsupported resource types', () => {
      const template: Template = {
        Resources: {
          TestEventRule: {
            Type: 'AWS::Events::Rule',
            Properties: {
              Name: 'test-rule'
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventRule'] as Resource);

      expect(result).toBeNull();
    });

    it('should return a finding if RetentionDays property is missing', () => {
      const template: Template = {
        Resources: {
          TestArchive: {
            Type: 'AWS::Events::Archive',
            Properties: {
              ArchiveName: 'test-archive',
              SourceArn: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              // RetentionDays is missing
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestArchive'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::Archive');
      expect(result?.resourceName).toBe('TestArchive');
      expect(result?.issue).toBe('EventBridge archive does not have a finite retention period configured. Events should not be kept in the archive for longer than necessary');
      expect(result?.fix).toBe('Set RetentionDays property to 30');
    });

    it('should return a finding if RetentionDays is set to 0 (infinite retention)', () => {
      const template: Template = {
        Resources: {
          TestArchive: {
            Type: 'AWS::Events::Archive',
            Properties: {
              ArchiveName: 'test-archive',
              SourceArn: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
              RetentionDays: 0 // Explicitly set to infinite retention
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestArchive'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::Archive');
      expect(result?.resourceName).toBe('TestArchive');
      expect(result?.issue).toBe('EventBridge archive does not have a finite retention period configured. Events should not be kept in the archive for longer than necessary');
      expect(result?.fix).toBe('Set RetentionDays property to 30');
    });
    
    it('should NOT return a finding if RetentionDays is set to any positive value', () => {
      const template: Template = {
        Resources: {
          TestArchive: {
            Type: 'AWS::Events::Archive',
            Properties: {
              ArchiveName: 'test-archive',
              SourceArn: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
              RetentionDays: 15 // Any positive value is acceptable
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestArchive'] as Resource);

      expect(result).toBeNull();
    });

    it('should not return a finding if RetentionDays is set to a finite value of at least 30 days', () => {
      const template: Template = {
        Resources: {
          TestArchive: {
            Type: 'AWS::Events::Archive',
            Properties: {
              ArchiveName: 'test-archive',
              SourceArn: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
              RetentionDays: 90 // Appropriate finite value
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestArchive'] as Resource);

      expect(result).toBeNull();
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::Events::Archive',
        Properties: {
          ArchiveName: 'test-archive',
          SourceArn: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
          RetentionDays: 0 // Even with invalid value, it should return null
        },
        LogicalId: 'TestArchive'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});
