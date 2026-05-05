import { describe, it, expect } from 'vitest';
import { ESH009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/009-audit-logs.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH009Rule', () => {
  const rule = new ESH009Rule();
  const stackName = 'test-stack';

  // Helper function to create test resources
  function createOpenSearchResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::OpenSearchService::Domain',
      Properties: {
        DomainName: 'test-domain',
        EngineVersion: 'OpenSearch_1.0',
        ClusterConfig: {
          InstanceType: 't3.small.search',
          InstanceCount: 2
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestOpenSearchDomain'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('ESH-009');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to the correct resource types', () => {
      expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Audit Log Configuration Tests', () => {
    it('should detect missing LogPublishingOptions', () => {
      // Arrange
      const domain = createOpenSearchResource();
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('OpenSearch domain audit logging not configured');
    });

    it('should detect disabled audit logs', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: false,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('OpenSearch domain audit logging not configured');
    });

    it('should detect missing AccessPolicies', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Configure AccessPolicies to control audit log access');
    });

    it('should detect empty AccessPolicies object', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: {
          Version: '2012-10-17',
          Statement: []
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('AccessPolicies is empty or missing statements');
    });

    it('should handle AccessPolicies as JSON string', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: JSON.stringify({
          Version: '2012-10-17',
          Statement: []
        })
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('AccessPolicies is empty or missing statements');
    });

    it('should pass with properly configured audit logs and access policies', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Principal: {
              AWS: 'arn:aws:iam::123456789012:role/AuditLogReaderRole'
            },
            Action: 'es:ESHttpGet',
            Resource: 'arn:aws:es:us-west-2:123456789012:domain/test-domain/*'
          }]
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should pass with AccessPolicies as JSON string', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: JSON.stringify({
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Principal: {
              AWS: 'arn:aws:iam::123456789012:role/AuditLogReaderRole'
            },
            Action: 'es:ESHttpGet',
            Resource: 'arn:aws:es:us-west-2:123456789012:domain/test-domain/*'
          }]
        })
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties in resource', () => {
      // Arrange
      const domain = {
        Type: 'AWS::OpenSearchService::Domain',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull(); // Should detect missing LogPublishingOptions
    });

    it('should handle malformed JSON string in AccessPolicies', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: '{ malformed json }'
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull(); // Should not fail on unparsable strings, might be CloudFormation functions
    });

    it('should handle AccessPolicies as CloudFormation parameter reference', () => {
      // Arrange
      const domain = createOpenSearchResource({
        LogPublishingOptions: {
          AUDIT_LOGS: {
            Enabled: true,
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-west-2:123456789012:log-group:opensearch-logs'
          }
        },
        AccessPolicies: { Ref: 'AccessPolicyParameter' }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull(); // Should fail because AccessPolicies object has no Statement property
    });
  });
});
