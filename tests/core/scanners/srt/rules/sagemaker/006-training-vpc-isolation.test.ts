import { describe, it, expect } from 'vitest';
import { SageMaker006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/006-training-vpc-isolation.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker006Rule', () => {
  const rule = new SageMaker006Rule();
  const stackName = 'test-stack';

  function createTrainingJobResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::TrainingJob',
      Properties: {
        AlgorithmSpecification: {
          TrainingImage: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-training-image:latest',
          TrainingInputMode: 'File'
        },
        RoleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
        VpcConfig: {
          SecurityGroupIds: ['sg-12345'],
          Subnets: ['subnet-12345']
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestTrainingJob'
    };
  }

  function createProcessingJobResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::ProcessingJob',
      Properties: {
        AppSpecification: {
          ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-processing-image:latest'
        },
        RoleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
        VpcConfig: {
          SecurityGroupIds: ['sg-12345'],
          Subnets: ['subnet-12345']
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestProcessingJob'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-006');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker training and processing resources', () => {
      expect(rule.appliesTo('AWS::SageMaker::TrainingJob')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::ProcessingJob')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::TransformJob')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(false);
    });
  });

  describe('TrainingJob Tests', () => {
    it('should flag TrainingJob without VPC configuration', () => {
      const trainingJob = createTrainingJobResource({ 
        VpcConfig: undefined,
        LogicalId: 'NoVpcTraining'
      });
      delete trainingJob.Properties.VpcConfig;
      
      const result = rule.evaluate(trainingJob, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('NoVpcTraining');
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
      expect(result?.fix).toContain('Add VpcConfig with SecurityGroupIds and Subnets');
    });

    it('should flag TrainingJob with missing SecurityGroupIds', () => {
      const trainingJob = createTrainingJobResource({ 
        VpcConfig: { Subnets: ['subnet-12345'] },
        LogicalId: 'NoSecurityGroups'
      });
      
      const result = rule.evaluate(trainingJob, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
      expect(result?.fix).toContain('Add SecurityGroupIds array to VpcConfig');
    });

    it('should flag TrainingJob with missing Subnets', () => {
      const trainingJob = createTrainingJobResource({ 
        VpcConfig: { SecurityGroupIds: ['sg-12345'] },
        LogicalId: 'NoSubnets'
      });
      
      const result = rule.evaluate(trainingJob, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
      expect(result?.fix).toContain('Add Subnets array to VpcConfig');
    });

    it('should not flag properly configured TrainingJob', () => {
      const trainingJob = createTrainingJobResource();
      
      const result = rule.evaluate(trainingJob, stackName);
      
      expect(result).toBeNull();
    });
  });

  describe('ProcessingJob Tests', () => {
    it('should flag ProcessingJob without VPC configuration', () => {
      const processingJob = createProcessingJobResource({ 
        VpcConfig: undefined,
        LogicalId: 'NoVpcProcessing'
      });
      delete processingJob.Properties.VpcConfig;
      
      const result = rule.evaluate(processingJob, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('NoVpcProcessing');
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
    });

    it('should flag ProcessingJob with network isolation disabled', () => {
      const processingJob = createProcessingJobResource({ 
        NetworkConfig: { EnableNetworkIsolation: false },
        LogicalId: 'NoIsolation'
      });
      
      const result = rule.evaluate(processingJob, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
      expect(result?.fix).toContain('Set NetworkConfig.EnableNetworkIsolation to true');
    });

    it('should not flag ProcessingJob with proper VPC and network isolation', () => {
      const processingJob = createProcessingJobResource({
        NetworkConfig: { EnableNetworkIsolation: true }
      });
      
      const result = rule.evaluate(processingJob, stackName);
      
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle resources with missing Properties', () => {
      const resource = {
        Type: 'AWS::SageMaker::TrainingJob',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker training or processing job lacks VPC network isolation for data protection');
    });

    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      const result = rule.evaluate(resource, stackName);
      
      expect(result).toBeNull();
    });
  });
});