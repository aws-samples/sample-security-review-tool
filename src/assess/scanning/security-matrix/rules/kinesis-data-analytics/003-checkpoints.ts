import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * KDA3 Rule: Configure backups and recovery checkpoints
 * 
 * Documentation: "Checkpoints are backups of application state that Kinesis Data Analytics automatically 
 * creates periodically and uses to restore from faults."
 */
export class KDA003Rule extends BaseRule {
  constructor() {
    super(
      'KDA-003',
      'HIGH',
      'Kinesis Data Analytics V2 application does not have checkpoints configured for backup and recovery',
      ['AWS::KinesisAnalyticsV2::Application']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::KinesisAnalyticsV2::Application') {
      return null;
    }

    // KDA3: Configure backups and recovery checkpoints for V2 applications
    return this.evaluateV2Application(resource, stackName);
  }

  private evaluateV2Application(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const applicationConfiguration = resource.Properties?.ApplicationConfiguration;
    
    if (!applicationConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add ApplicationConfiguration with checkpointing enabled for backup and recovery.`
      );
    }

    // Check Flink application checkpointing
    const flinkConfig = applicationConfiguration.FlinkApplicationConfiguration;
    if (flinkConfig) {
      const checkpointConfig = flinkConfig.CheckpointConfiguration;
      
      if (!checkpointConfig || checkpointConfig.ConfigurationType === 'CUSTOM') {
        const checkpointingEnabled = checkpointConfig?.CheckpointingEnabled;
        
        if (checkpointingEnabled === false) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set CheckpointingEnabled to true in FlinkApplicationConfiguration.CheckpointConfiguration.`
          );
        }
      }
    }

    return null;
  }
}

export default new KDA003Rule();
