import { describe, it, expect } from 'vitest';
import MSK009Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/009-cloudtrail-monitoring.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK009Rule - CloudTrail Monitoring', () => {
  const rule = MSK009Rule;

  it('should pass when MSK cluster has CloudTrail with default configuration', () => {
    const mskResource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const cloudTrailResource: CloudFormationResource = {
      Type: 'AWS::CloudTrail::Trail',
      LogicalId: 'TestCloudTrail',
      Properties: {
        IsLogging: true,
        S3BucketName: 'my-cloudtrail-bucket'
      }
    };

    const result = rule.evaluate(mskResource, 'test-stack', [mskResource, cloudTrailResource]);
    expect(result).toBeNull();
  });

  it('should fail when MSK cluster has no CloudTrail with informational note', () => {
    const mskResource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const result = rule.evaluate(mskResource, 'test-stack', [mskResource]);
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Configure CloudTrail to monitor MSK API calls by adding an AWS::CloudTrail::Trail resource with management events enabled');
  });

  it('should fail when CloudTrail logging is disabled', () => {
    const mskResource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const cloudTrailResource: CloudFormationResource = {
      Type: 'AWS::CloudTrail::Trail',
      LogicalId: 'TestCloudTrail',
      Properties: {
        IsLogging: false,
        S3BucketName: 'my-cloudtrail-bucket'
      }
    };

    const result = rule.evaluate(mskResource, 'test-stack', [mskResource, cloudTrailResource]);
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
  });

  it('should fail when management events are explicitly disabled', () => {
    const mskResource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const cloudTrailResource: CloudFormationResource = {
      Type: 'AWS::CloudTrail::Trail',
      LogicalId: 'TestCloudTrail',
      Properties: {
        IsLogging: true,
        EventSelectors: [{
          ReadWriteType: 'All',
          IncludeManagementEvents: false
        }]
      }
    };

    const result = rule.evaluate(mskResource, 'test-stack', [mskResource, cloudTrailResource]);
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
  });

  it('should ignore non-MSK resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestS3Bucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when no allResources provided with guidance message', () => {
    const mskResource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const result = rule.evaluate(mskResource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster should have CloudTrail monitoring configured');
  });
});