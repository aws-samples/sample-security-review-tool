import { describe, it, expect } from 'vitest';
import { ESH006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/006-off-peak-window.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH006Rule', () => {
  const rule = new ESH006Rule();
  const stackName = 'test-stack';

  function createOpenSearchResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::OpenSearchService::Domain',
      Properties: {
        DomainName: 'test-domain',
        ...props
      },
      LogicalId: 'TestOpenSearchDomain'
    };
  }

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('ESH-006');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
    expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
  });

  it('should detect missing OffPeakWindowOptions', () => {
    const domain = createOpenSearchResource();
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('OpenSearch domain missing off-peak window configuration');
  });

  it('should detect OffPeakWindowOptions with Enabled set to false', () => {
    const domain = createOpenSearchResource({
      OffPeakWindowOptions: {
        Enabled: false
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
  });

  it('should pass with OffPeakWindowOptions enabled', () => {
    const domain = createOpenSearchResource({
      OffPeakWindowOptions: {
        Enabled: true,
        OffPeakWindow: {
          WindowStartTime: {
            Hours: 2,
            Minutes: 0
          }
        }
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });

  it('should not apply to AWS::Elasticsearch::Domain', () => {
    const domain = {
      Type: 'AWS::Elasticsearch::Domain',
      Properties: {
        DomainName: 'test-domain'
      },
      LogicalId: 'TestElasticsearchDomain'
    };
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });
});