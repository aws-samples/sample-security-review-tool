import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT-028 Rule: Define a backup and recovery plan for IoT devices and data
 * 
 * Documentation: AWS IoT devices and data should have backup and recovery mechanisms.
 * This rule checks for backup strategies such as S3 buckets with versioning,
 * DynamoDB tables with point-in-time recovery, IoT Analytics datastores with retention periods,
 * and backup-related topic rules.
 * 
 * Recovery mechanisms checked include Lambda functions for recovery operations,
 * Step Functions workflows, and CloudWatch alarms that could trigger recovery actions.
 * 
 * Resiliency features checked include IoT Device Defender for health monitoring,
 * multi-AZ deployments, edge computing resources (Greengrass), and redundant IoT SiteWise gateways.
 */
export class IoT028Rule extends BaseRule {
  constructor() {
    super(
      'IOT-028',
      'HIGH',
      'IoT resources lack backup and recovery mechanisms',
      [
        'AWS::IoT::Thing',
        'AWS::IoT::ThingGroup',
        'AWS::IoTSiteWise::Gateway',
        'AWS::IoTSiteWise::Portal',
        'AWS::IoTAnalytics::Datastore',
        'AWS::IoTTwinMaker::Workspace'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) {
      return null;
    }

    const allRes = allResources || [];

    // Check for backup mechanisms
    const hasBackup = this.hasBackupMechanism(resource, allRes);
    const hasRecovery = this.hasRecoveryMechanism(resource, allRes);
    const hasResiliency = this.hasResiliencyFeatures(resource, allRes);

    if (!hasBackup && !hasRecovery && !hasResiliency) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no backup, recovery, or resiliency mechanisms)`,
        `Implement backup strategies using S3, DynamoDB backups, or edge resiliency features.`
      );
    }

    return null;
  }

  private hasBackupMechanism(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check for S3 backup destinations
    const hasS3Backup = allResources.some(r =>
      r.Type === 'AWS::S3::Bucket' &&
      (r.Properties?.VersioningConfiguration?.Status === 'Enabled' ||
        r.Properties?.ReplicationConfiguration)
    );

    // Check for DynamoDB backup
    const hasDynamoBackup = allResources.some(r =>
      r.Type === 'AWS::DynamoDB::Table' &&
      (r.Properties?.BackupPolicy?.PointInTimeRecoveryEnabled === true ||
        r.Properties?.StreamSpecification)
    );

    // Check for IoT Analytics backup
    if (resource.Type === 'AWS::IoTAnalytics::Datastore') {
      return resource.Properties?.RetentionPeriod ||
        resource.Properties?.DatastoreStorage?.ServiceManagedS3;
    }

    // Check for backup-related topic rules
    const hasBackupTopicRule = allResources.some(r =>
      r.Type === 'AWS::IoT::TopicRule' &&
      r.Properties?.TopicRulePayload?.Actions?.some((action: any) =>
        action.s3 || action.dynamodb || action.kinesis
      )
    );

    return hasS3Backup || hasDynamoBackup || hasBackupTopicRule;
  }

  private hasRecoveryMechanism(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check for Lambda functions that could handle recovery
    const hasRecoveryLambda = allResources.some(r =>
      r.Type === 'AWS::Lambda::Function' &&
      JSON.stringify(r.Properties).toLowerCase().includes('recover')
    );

    // Check for Step Functions for recovery workflows
    const hasRecoveryWorkflow = allResources.some(r =>
      r.Type === 'AWS::StepFunctions::StateMachine' &&
      JSON.stringify(r.Properties).toLowerCase().includes('recover')
    );

    // Check for CloudWatch alarms that could trigger recovery
    const hasRecoveryAlarms = allResources.some(r =>
      r.Type === 'AWS::CloudWatch::Alarm' &&
      r.Properties?.AlarmActions?.length > 0
    );

    return hasRecoveryLambda || hasRecoveryWorkflow || hasRecoveryAlarms;
  }

  private hasResiliencyFeatures(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check for IoT Device Defender for device health monitoring
    const hasDeviceDefender = allResources.some(r =>
      r.Type === 'AWS::IoT::SecurityProfile'
    );

    // Check for multiple availability zones or regions
    const hasMultiAZ = this.hasMultiAZDeployment(allResources);

    // Check for edge computing resources (Greengrass)
    const hasEdgeComputing = allResources.some(r =>
      r.Type.includes('Greengrass') ||
      JSON.stringify(r.Properties).toLowerCase().includes('greengrass')
    );

    // Check for IoT SiteWise edge gateway redundancy
    if (resource.Type === 'AWS::IoTSiteWise::Gateway') {
      const gateways = allResources.filter(r => r.Type === 'AWS::IoTSiteWise::Gateway');
      return gateways.length > 1;
    }

    return hasDeviceDefender || hasMultiAZ || hasEdgeComputing;
  }

  private hasMultiAZDeployment(allResources: CloudFormationResource[]): boolean {
    // Check for resources deployed across multiple AZs
    const subnets = allResources.filter(r => r.Type === 'AWS::EC2::Subnet');
    const uniqueAZs = new Set(subnets.map(s => s.Properties?.AvailabilityZone).filter(Boolean));

    return uniqueAZs.size > 1;
  }
}

export default new IoT028Rule();
