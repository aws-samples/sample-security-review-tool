import { describe, it, expect } from 'vitest';
import { Timestream001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/timestream/001-cloudtrail-loggings.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Timestream001Rule', () => {
  const rule = new Timestream001Rule();
  const stackName = 'test-stack';

  // Helper function to create Timestream database test resources
  function createTimestreamDatabaseResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Timestream::Database',
      Properties: {
        DatabaseName: 'TestDatabase',
        ...props
      },
      LogicalId: props.LogicalId || 'TestTimestreamDatabase'
    };
  }

  // Helper function to create CloudTrail test resources
  function createCloudTrailResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::CloudTrail::Trail',
      Properties: {
        S3BucketName: 'test-bucket',
        IsLogging: true,
        ...props
      },
      LogicalId: props.LogicalId || 'TestCloudTrail'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('TIMESTREAM-001');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Timestream database resources', () => {
      expect(rule.appliesTo('AWS::Timestream::Database')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Timestream Database Tests', () => {
    it('should flag database when no CloudTrail resources exist', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const allResources: CloudFormationResource[] = [database];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Timestream::Database');
      expect(result?.resourceName).toBe('TestTimestreamDatabase');
      expect(result?.issue).toContain('Timestream resources deployed without CloudTrail logging configured');
      expect(result?.fix).toContain('Create an AWS::CloudTrail::Trail resource');
    });

    it('should flag database when CloudTrail exists but IsLogging is false', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const cloudTrail = createCloudTrailResource({ IsLogging: false });
      const allResources: CloudFormationResource[] = [database, cloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Timestream resources deployed without CloudTrail logging configured');
      expect(result?.fix).toContain('Ensure CloudTrail trail has IsLogging enabled');
    });

    it('should flag database when CloudTrail exists but S3BucketName is missing', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const cloudTrail = createCloudTrailResource({ S3BucketName: undefined });
      const allResources: CloudFormationResource[] = [database, cloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Timestream resources deployed without CloudTrail logging configured');
      expect(result?.fix).toContain('Ensure CloudTrail trail has IsLogging enabled');
    });

    it('should not flag database when CloudTrail is properly configured', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const cloudTrail = createCloudTrailResource();
      const allResources: CloudFormationResource[] = [database, cloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag database when multiple CloudTrails exist and at least one is properly configured', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const invalidCloudTrail = createCloudTrailResource({ IsLogging: false, LogicalId: 'InvalidCloudTrail' });
      const validCloudTrail = createCloudTrailResource({ LogicalId: 'ValidCloudTrail' });
      const allResources: CloudFormationResource[] = [database, invalidCloudTrail, validCloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties in Timestream database', () => {
      // Arrange
      const database = {
        Type: 'AWS::Timestream::Database',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      const cloudTrail = createCloudTrailResource();
      const allResources: CloudFormationResource[] = [database, cloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).toBeNull(); // Should not flag because CloudTrail is properly configured
    });

    it('should handle missing Properties in Timestream database with no CloudTrail', () => {
      // Arrange
      const database = {
        Type: 'AWS::Timestream::Database',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      const allResources: CloudFormationResource[] = [database];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Timestream resources deployed without CloudTrail logging configured');
    });

    it('should handle CloudFormation intrinsic functions in CloudTrail properties', () => {
      // Arrange
      const database = createTimestreamDatabaseResource();
      const cloudTrail = createCloudTrailResource({
        IsLogging: { Ref: 'IsLoggingParameter' },
        S3BucketName: { 'Fn::GetAtt': ['LogBucket', 'BucketName'] }
      });
      const allResources: CloudFormationResource[] = [database, cloudTrail];
      
      // Act
      const result = rule.evaluate(database, stackName, allResources);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Set CloudTrail IsLogging property to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time');
    });

    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });
});
