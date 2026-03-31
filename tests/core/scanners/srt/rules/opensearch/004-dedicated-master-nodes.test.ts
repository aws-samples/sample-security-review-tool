import { describe, it, expect } from 'vitest';
import { ESH004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/004-dedicated-master-nodes.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH004Rule', () => {
  const rule = new ESH004Rule();
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
    expect(rule.id).toBe('ESH-004');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
    expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
  });

  it('should detect missing ClusterConfig', () => {
    const domain = createOpenSearchResource();
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('OpenSearch domain not using dedicated master nodes');
  });

  it('should detect DedicatedMasterEnabled set to false', () => {
    const domain = createOpenSearchResource({
      ClusterConfig: {
        DedicatedMasterEnabled: false
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
  });

  it('should pass with DedicatedMasterEnabled set to true and MasterInstanceCount', () => {
    const domain = createOpenSearchResource({
      ClusterConfig: {
        DedicatedMasterEnabled: true,
        MasterInstanceCount: 3
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });


});