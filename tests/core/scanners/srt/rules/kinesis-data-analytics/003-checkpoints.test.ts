import { describe, it, expect } from 'vitest';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import KDA003Rule from '../../../../../../src/assess/scanning/security-matrix/rules/kinesis-data-analytics/003-checkpoints.cf.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner';

describe('KDA-003: Kinesis Data Analytics checkpoints rule', () => {
  const stackName = 'test-stack';

  function createV1Application(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::KinesisAnalytics::Application',
      LogicalId: 'TestKDAApp',
      Properties: {
        ApplicationName: 'test-app',
        ...props
      }
    };
  }

  function createV2Application(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::KinesisAnalyticsV2::Application',
      LogicalId: 'TestKDAV2App',
      Properties: {
        ApplicationName: 'test-app-v2',
        RuntimeEnvironment: 'FLINK-1_13',
        ...props
      }
    };
  }



  describe('V2 Applications', () => {
    it('passes when V2 application has default configuration', () => {
      const resource = createV2Application({
        ApplicationConfiguration: {
          FlinkApplicationConfiguration: {
            CheckpointConfiguration: {
              ConfigurationType: 'DEFAULT'
            }
          }
        }
      });

      const result = KDA003Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('passes when V2 application has checkpointing explicitly enabled', () => {
      const resource = createV2Application({
        ApplicationConfiguration: {
          FlinkApplicationConfiguration: {
            CheckpointConfiguration: {
              ConfigurationType: 'CUSTOM',
              CheckpointingEnabled: true
            }
          }
        }
      });

      const result = KDA003Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when V2 application has no ApplicationConfiguration', () => {
      const resource = createV2Application();

      const result = KDA003Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Analytics V2 application does not have checkpoints configured');
      expect((result as ScanResult).fix).toContain('Add ApplicationConfiguration with checkpointing enabled');
    });

    it('fails when V2 application has checkpointing disabled', () => {
      const resource = createV2Application({
        ApplicationConfiguration: {
          FlinkApplicationConfiguration: {
            CheckpointConfiguration: {
              ConfigurationType: 'CUSTOM',
              CheckpointingEnabled: false
            }
          }
        }
      });

      const result = KDA003Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('Kinesis Data Analytics V2 application does not have checkpoints configured');
      expect((result as ScanResult).fix).toContain('Set CheckpointingEnabled to true');
    });

    it('passes when V2 application has SQL configuration', () => {
      const resource = createV2Application({
        ApplicationConfiguration: {
          SqlApplicationConfiguration: {
            Inputs: [
              {
                NamePrefix: 'test-input',
                InputSchema: {
                  RecordColumns: [
                    {
                      Name: 'test-column',
                      SqlType: 'VARCHAR(32)'
                    }
                  ]
                }
              }
            ]
          }
        }
      });

      const result = KDA003Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  it('ignores V1 applications and other resources', () => {
    const v1Resource = createV1Application();
    const v1Result = KDA003Rule.evaluate(v1Resource, stackName);
    expect(v1Result).toBeNull();

    const otherResource: CloudFormationResource = {
      Type: 'AWS::Kinesis::Stream',
      LogicalId: 'TestStream',
      Properties: {
        ShardCount: 1
      }
    };
    const otherResult = KDA003Rule.evaluate(otherResource, stackName);
    expect(otherResult).toBeNull();
  });
});